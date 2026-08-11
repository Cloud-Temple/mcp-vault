# -*- coding: utf-8 -*-
"""
Contrat de reproductibilité de l'image (issue #125).

## Le défaut

`src/mcp_vault/server.py` importe `mcp.server.fastmcp.FastMCP`. Le Dockerfile
n'installait que `requirements.txt`, où MCP est déclaré par un PLANCHER
(`mcp[cli]>=1.23.0`). Le jour où `mcp 2.0.0` est paru en amont — sans ce module
—, toute construction fraîche a cessé de démarrer :
`ModuleNotFoundError: No module named 'mcp.server.fastmcp'`, conteneur code 1.

Ce n'était pas une régression de la version en cours : la ligne est non bornée
depuis la v0.4.5 et le Dockerfile n'a JAMAIS consommé `requirements.lock`, livré
dans ce même commit. Toute version reconstruite ce jour-là échouait à
l'identique. Le déclencheur était EXTERNE — une publication amont.

## Ce que ces tests verrouillent

Le correctif déplace l'autorité des versions installées vers `requirements.lock`.
Cela crée une dette symétrique : si le verrou dérive sous un plancher déclaré,
on perd silencieusement une garantie durement acquise (`boto3>=1.38.43` porte
`PutObject.IfMatch`, dont dépend `scripts/rotate_bootstrap_key.py` ;
`uvicorn==0.42.0` porte la sémantique de ré-émission du SIGTERM dont dépend
l'exécution du lifespan d'arrêt du coffre — issues #121 et #110).

Ces tests ne remplacent PAS la preuve réelle (construire l'image et démarrer le
conteneur) : ils la complètent en s'exécutant sans Docker, donc partout.

Classification VÉRIFIÉE en retirant le correctif et en rejouant le fichier
(`git stash` des 3 fichiers modifiés) — 4 échecs, 2 succès :

- **RED sans le correctif** (preuves du défaut) : `..._consumes_the_lock`,
  `..._bounds_mcp_below_the_breaking_major`, `..._verifies_the_import...`,
  `..._never_installs_the_test_tooling`.
- **Déjà GREEN** (gardes contre une dérive FUTURE du verrou, pas des preuves) :
  `..._satisfies_every_declared_floor`, `..._is_pinned_in_the_lock`.
"""

import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent

# Outils présents dans `requirements.txt` mais délibérément ABSENTS de l'image de
# production (durcissement P2-8 : les tests ne sont pas embarqués en prod). Le
# verrou n'a donc pas à les épingler.
TEST_ONLY = {"pytest", "pytest-asyncio"}


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def _requirements() -> dict[str, Requirement]:
    """Dépendances déclarées dans `requirements.txt`, indexées par nom canonique."""
    parsed: dict[str, Requirement] = {}
    for raw in _read("requirements.txt").split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        parsed[canonicalize_name(req.name)] = req
    return parsed


def _lock() -> dict[str, Version]:
    """Versions épinglées par `requirements.lock`, indexées par nom canonique."""
    pinned: dict[str, Version] = {}
    for raw in _read("requirements.lock").split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, version = line.partition("==")
        assert version, f"ligne de verrou non épinglée (attendu `paquet==version`) : {line!r}"
        pinned[canonicalize_name(name)] = Version(version)
    return pinned


def _pip_install_commands() -> list[str]:
    """Les `RUN pip install` du Dockerfile, un par stage qui installe."""
    return [
        match.group(0)
        for match in re.finditer(r"^RUN pip install.*$", _read("Dockerfile"), re.M)
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 1-2 : preuves du défaut (RED sur `main` avant correctif)
# ─────────────────────────────────────────────────────────────────────────────

def test_every_dockerfile_pip_install_consumes_the_lock() -> None:
    """
    LE défaut de #125 : le verrou était livré mais aucun stage ne le consommait,
    donc l'image installait des planchers et non des versions verrouillées.
    """
    commands = _pip_install_commands()
    assert commands, "aucun `RUN pip install` trouvé dans le Dockerfile : test à revoir"

    without_lock = [cmd for cmd in commands if "requirements.lock" not in cmd]
    assert without_lock == [], (
        "des stages installent des dépendances SANS consommer requirements.lock — "
        "l'image ne correspond alors pas au verrou livré et une publication amont "
        f"peut la casser : {without_lock}"
    )


def test_requirements_bounds_mcp_below_the_breaking_major() -> None:
    """
    Le verrou protège l'IMAGE. Un `pip install -r requirements.txt` hors Docker
    (poste de développement, procédure du README) réinstallerait le défaut.
    """
    mcp = _requirements().get("mcp")
    assert mcp is not None, "mcp absent de requirements.txt"
    assert not mcp.specifier.contains(Version("2.0.0"), prereleases=True), (
        f"requirements.txt autorise mcp 2.0.0 ({mcp.specifier}) — or ce majeur a "
        "supprimé `mcp.server.fastmcp`, importé par src/mcp_vault/server.py"
    )
    assert mcp.specifier.contains(Version("1.26.0")), (
        f"la borne haute ne doit pas exclure la version verrouillée : {mcp.specifier}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3-5 : gardes de non-régression contre une dérive FUTURE du verrou
# ─────────────────────────────────────────────────────────────────────────────

def test_lock_satisfies_every_declared_floor() -> None:
    """
    Le verrou fait désormais autorité pour l'image : il doit donc respecter
    TOUTES les contraintes déclarées. Sans ce test, un verrou régénéré pourrait
    repasser sous `boto3>=1.38.43` (perte de `PutObject.IfMatch`, #121) ou
    changer `uvicorn==0.42.0` (perte du chemin d'arrêt du coffre, #110) sans que
    rien ne le signale avant la production.
    """
    lock = _lock()
    violations = []
    for name, req in _requirements().items():
        if name in TEST_ONLY:
            continue
        pinned = lock.get(name)
        if pinned is None:
            continue  # couvert par le test dédié ci-dessous
        if not req.specifier.contains(pinned, prereleases=True):
            violations.append(f"{name}: verrou {pinned} viole {req.specifier}")

    assert violations == [], (
        "le verrou ne respecte plus les contraintes déclarées dans "
        f"requirements.txt : {violations}"
    )


def test_every_runtime_requirement_is_pinned_in_the_lock() -> None:
    """
    Réciproque : une dépendance d'exécution ajoutée au `.txt` sans être ajoutée
    au verrou serait, dans l'image, résolue librement — exactement le mécanisme
    qui a produit #125, réintroduit une dépendance à la fois.
    """
    lock = _lock()
    missing = sorted(
        name for name in _requirements()
        if name not in TEST_ONLY and name not in lock
    )
    assert missing == [], (
        "dépendances d'exécution déclarées mais NON verrouillées (elles seraient "
        f"résolues librement dans l'image) : {missing}"
    )


# NOTE (revue pré-commit) : un test « le verrou épingle mcp en 1.x » a été retiré
# ici — il est logiquement impliqué par les deux tests ci-dessus (le `.txt` borne
# `<2`, et le verrou doit satisfaire tous les specifiers déclarés). Le garder
# n'ajoutait aucun invariant, seulement une maintenance.


# ─────────────────────────────────────────────────────────────────────────────
# 6-7 : garde de construction et durcissement de l'image de production
# ─────────────────────────────────────────────────────────────────────────────

def test_build_verifies_the_import_that_broke_production() -> None:
    """
    La construction doit échouer sur une résolution incompatible — le défaut ne
    doit plus se découvrir au démarrage du conteneur, en aval de la livraison.
    """
    dockerfile = _read("Dockerfile")
    guards = re.findall(
        r"^RUN python -c .from mcp\.server\.fastmcp import FastMCP.$",
        dockerfile,
        re.M,
    )
    installs = _pip_install_commands()
    assert len(guards) >= len(installs), (
        f"{len(installs)} stage(s) installent des dépendances mais seulement "
        f"{len(guards)} garde(s) d'import à la construction — un stage peut "
        "produire une image qui ne démarre pas"
    )


def test_production_stage_never_installs_the_test_tooling() -> None:
    """
    Le durcissement P2-8 (tests hors image de production) ne doit pas être perdu
    en passant le verrou : `requirements.txt` porte pytest, et ne doit donc être
    installé QUE dans le stage de test.
    """
    dockerfile = _read("Dockerfile")
    stages = re.split(r"^FROM ", dockerfile, flags=re.M)
    production = [s for s in stages if s.startswith("python:3.12-slim") and "AS production" in s]
    assert len(production) == 1, "stage de production introuvable ou dupliqué"

    installs = re.findall(r"^RUN pip install.*$", production[0], re.M)
    assert installs, "le stage de production n'installe aucune dépendance : test à revoir"
    with_txt = [cmd for cmd in installs if "requirements.txt" in cmd]
    assert with_txt == [], (
        "le stage de production installe requirements.txt, qui embarque pytest et "
        f"pytest-asyncio dans l'image livrée : {with_txt}"
    )
