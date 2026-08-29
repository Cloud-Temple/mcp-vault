# -*- coding: utf-8 -*-
"""
Contrat de reproductibilité de l'image (issue #125).

## Le défaut

Jusqu'à la v0.19.1, `src/mcp_vault/server.py` importait
`mcp.server.fastmcp.FastMCP`. Le Dockerfile n'installait que
`requirements.txt`, où MCP était déclaré par un PLANCHER
(`mcp[cli]>=1.23.0`). Le jour où `mcp 2.0.0` est paru en amont — sans ce module
—, toute construction fraîche a cessé de démarrer. La v0.20.0 migre vers
`mcp.server.MCPServer` ; le verrou et la garde d'import continuent de protéger
chaque stage contre une publication amont incompatible.

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
  `..._bounds_mcp_to_the_supported_v2_major`, `..._verifies_the_import...`,
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
# verrou n'a donc pas à les épingler — mais ils sont épinglés dans le `.txt`,
# car la chaîne de test est ce qui garde la release. `pluggy` et `iniconfig`
# sont les transitives de pytest ; `packaging`, la troisième, est déjà dans le
# verrou au titre des dépendances d'exécution.
TEST_ONLY = {"pytest", "pytest-asyncio", "pluggy", "iniconfig"}


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


def _stages() -> dict[str, str]:
    """Corps de chaque stage du Dockerfile, indexé par son nom `AS <nom>`.

    Le découpage par stage est nécessaire aux tests qui portent sur UN stage
    précis : compter des occurrences sur le fichier entier laisserait passer
    deux gardes dans le même stage et aucun dans un autre.
    """
    stages: dict[str, str] = {}
    parts = re.split(r"^FROM\s+(.*)$", _read("Dockerfile"), flags=re.M)
    # parts = [préambule, en-tête1, corps1, en-tête2, corps2, ...]
    for header, body in zip(parts[1::2], parts[2::2]):
        match = re.search(r"\bAS\s+(\S+)", header)
        if match:
            stages[match.group(1)] = body
    assert stages, "aucun stage nommé trouvé dans le Dockerfile : test à revoir"
    return stages


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


def test_requirements_bounds_mcp_to_the_supported_v2_major() -> None:
    """Le développement et l'image doivent résoudre le même majeur MCP v2."""
    mcp = _requirements().get("mcp")
    assert mcp is not None, "mcp absent de requirements.txt"
    assert mcp.specifier.contains(Version("2.1.1"), prereleases=True), (
        f"requirements.txt exclut la version v2 verrouillée : {mcp.specifier}"
    )
    assert not mcp.specifier.contains(Version("1.26.0"), prereleases=True), (
        f"requirements.txt autorise encore le SDK v1 : {mcp.specifier}"
    )
    assert not mcp.specifier.contains(Version("3.0.0"), prereleases=True), (
        f"requirements.txt autorise un futur majeur non audité : {mcp.specifier}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3-4 : gardes de non-régression contre une dérive FUTURE du verrou
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


# NOTE : une assertion séparée « le verrou épingle mcp en 2.x » serait
# logiquement impliquée par les deux tests ci-dessus (le `.txt` borne `>=2,<3`
# et le verrou doit satisfaire tous les specifiers déclarés).


# ─────────────────────────────────────────────────────────────────────────────
# 5-6 : garde de construction et durcissement de l'image de production
# ─────────────────────────────────────────────────────────────────────────────

def test_build_verifies_the_import_that_broke_production() -> None:
    """
    La construction doit échouer sur une résolution incompatible — le défaut ne
    doit plus se découvrir au démarrage du conteneur, en aval de la livraison.

    La vérification est faite STAGE PAR STAGE (revue) : un simple comptage
    global laisserait passer deux gardes dans le même stage, en laissant un
    autre stage capable de produire une image qui ne démarre pas.
    """
    guard = re.compile(r"^RUN python -c .from mcp\.server import MCPServer.$", re.M)

    unguarded = [
        name for name, body in _stages().items()
        if re.search(r"^RUN pip install", body, re.M) and not guard.search(body)
    ]
    assert unguarded == [], (
        "stages installant des dépendances sans garde d'import à la "
        f"construction : {unguarded}"
    )


def test_production_stage_never_installs_the_test_tooling() -> None:
    """
    Le durcissement P2-8 (tests hors image de production) ne doit pas être perdu
    en passant le verrou : `requirements.txt` porte pytest, et ne doit donc être
    installé QUE dans le stage de test.
    """
    production = _stages().get("production")
    assert production is not None, "stage `production` introuvable : test à revoir"

    installs = re.findall(r"^RUN pip install.*$", production, re.M)
    assert installs, "le stage de production n'installe aucune dépendance : test à revoir"
    with_txt = [cmd for cmd in installs if "requirements.txt" in cmd]
    assert with_txt == [], (
        "le stage de production installe requirements.txt, qui embarque "
        f"l'outillage de test dans l'image livrée : {with_txt}"
    )

    # Vérifier la SOURCE ne suffit pas (revue) : le stage de production installe
    # le verrou, donc y ajouter `pytest` embarquerait l'outillage de test tout en
    # laissant ce test vert. On contrôle donc aussi le CONTENU du verrou.
    leaked = sorted(TEST_ONLY & _lock().keys())
    assert leaked == [], (
        "outillage de test épinglé dans requirements.lock — donc installé dans "
        f"l'image de PRODUCTION, qui n'installe que le verrou : {leaked}"
    )
