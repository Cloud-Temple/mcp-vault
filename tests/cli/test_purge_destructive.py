#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Opérations de purge DESTRUCTIVES — contrat fail-close (issue #50).

## Origine

Ces invariants étaient verrouillés uniquement par les anciens tests du shell
interactif (`main:tests/cli/test_purge_shell.py` et
`main:tests/cli/test_purge_shell_mission_binding.py`, supprimés avec lui). Le shell est supprimé (issue #128) : la protection, elle, vit dans
les commandes Click — mais **aucun test ne la couvrait de ce côté**. Sans ce
portage, supprimer le shell aurait laissé deux opérations irréversibles sans
filet.

## Ce qui est verrouillé

`token purge-revoked` et `mission-binding purge` suppriment définitivement des
enregistrements. Le contrat est le même pour les deux :

- `--older-than` invalide ou incomplet → **aucun appel réseau**, ni aperçu ni
  purge. La valeur de rétention ne doit jamais être devinée ;
- un aperçu (`dry_run=True`) en échec → la purge effective n'est **jamais**
  déclenchée. On ne supprime pas sur la foi d'un décompte qu'on n'a pas obtenu ;
- `--yes` n'exécute la purge qu'**après** un aperçu réussi ;
- sans `--yes` → aperçu seulement (le prompt de confirmation est refusé ici,
  ce qui simule un opérateur qui renonce).

On intercepte `httpx.AsyncClient` et on inspecte les POST réellement émis : c'est
l'absence de POST `dry_run=False` qui prouve qu'aucune suppression n'a eu lieu.
Vérifier un code de retour ne le prouverait pas.

## Preuve de mutation — MESURÉE sur les 40 tests

| Mutation appliquée à `scripts/cli/commands.py` | Échecs |
| --- | --- |
| aperçu retiré (`dry_run=True` → `False`) | 22 |
| `if n == 0` au lieu d'une preuve positive stricte | 12 |
| `abort=True` → `abort=False` | 2 |
| rétention par défaut `30` → `0` | 2 |
| borne `IntRange(min=0)` retirée | 2 |
| en-têtes d'authentification retirés | 2 |
| endpoint tokens dirigé vers celui des bindings | 1 |
| reprise ajoutée après échec réseau de la purge | 1 |

Six de ces huit mutations ont été ajoutées au fil de revues successives, chacune
après avoir constaté que les tests d'alors restaient VERTS en sa présence. Rien
ne protégeait : la rétention par défaut, le refus d'une rétention négative,
l'ENDPOINT appelé (une purge de tokens dirigée vers l'endpoint des liaisons de
mission passait inaperçue et supprimerait la mauvaise famille d'objets), la
lisibilité du décompte, les en-têtes d'authentification, ni l'absence de reprise
après un échec réseau.

La mutation `abort` a demandé TROIS tentatives avant d'être réellement détectée
(voir `_Confirm`). Un test de confirmation mal construit reste vert quoi qu'il
arrive : il ne protège rien tout en donnant l'impression du contraire.
"""

import os
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from cli.commands import cli


class _Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class _FakeHttp:
    """Faux httpx.AsyncClient : enregistre chaque POST et débite une file de réponses."""

    def __init__(self, queue, echec_au=None):
        self._queue = list(queue)
        self._echec_au = echec_au        # numéro du POST qui lèvera
        self.posts = []          # payloads json réellement POSTés
        self.urls = []           # URL de chaque POST
        self.headers = []        # en-têtes de chaque POST

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        self.posts.append(json)
        if self._echec_au is not None and len(self.posts) == self._echec_au:
            self.urls.append(url)
            self.headers.append(headers or {})
            raise RuntimeError("délai d'attente réseau simulé")
        self.urls.append(url)
        self.headers.append(headers or {})
        return _Resp(self._queue.pop(0) if self._queue
                     else {"status": "error", "message": "no response"})


def _run(argv, queue, confirme=True, echec_au=None):
    """
    Exécute la commande Click ; `confirme` simule la réponse au prompt.

    NUANCE MESURÉE : le code appelle `click.confirm(..., abort=True)`, qui LÈVE
    `click.Abort` sur un refus — il ne renvoie pas `False`, et l'appelant ne
    teste aucune valeur de retour. Simuler le refus par `return_value=False`
    laissait donc la purge s'exécuter : le test passait à côté de son objet.
    On simule le refus par l'exception réelle.
    """
    import click as _click

    fake = _FakeHttp(queue, echec_au=echec_au)
    confirm = _Confirm(refuse=not confirme)
    with patch("httpx.AsyncClient", return_value=fake), \
         patch("click.confirm", confirm):
        # `--token` explicite : sans lui, l'en-tête viendrait de l'environnement
        # et l'assertion d'authentification ne prouverait rien.
        resultat = CliRunner().invoke(cli, ["--token", _JETON_TEST] + argv)
    return fake, resultat, confirm


_JETON_TEST = "jeton-de-test-non-secret"


class _Confirm:
    """
    Simulacre de `click.confirm` qui ENREGISTRE ses appels.

    Deux pièges successifs ont été rencontrés ici, tous deux relevés en revue :

    1. simuler le refus par `return_value=False` ne refuse rien — l'appelant
       n'examine aucune valeur de retour, c'est `abort=True` qui interrompt par
       exception ;
    2. lever `Abort` inconditionnellement dans le simulacre ne prouve pas
       davantage : la mutation `abort=True` → `abort=False` reste alors verte.
       Assertionner À L'INTÉRIEUR du simulacre ne suffit pas non plus — le
       lanceur Click capture l'exception, qui interrompt l'exécution exactement
       comme le ferait un refus, et le test passe pour la mauvaise raison.

    Le simulacre se contente donc d'enregistrer ; c'est le TEST qui vérifie que
    `abort=True` a bien été demandé.
    """

    def __init__(self, refuse):
        self.refuse = refuse
        self.appels = []

    def __call__(self, *args, **kwargs):
        self.appels.append(kwargs)
        if self.refuse:
            import click as _click
            raise _click.Abort()
        return True


# Les deux commandes partagent le contrat : on les paramétrise plutôt que de
# dupliquer, pour qu'un invariant ajouté couvre mécaniquement les deux.
_PURGES = [
    pytest.param(["token", "purge-revoked"], "candidates",
                 "/admin/api/tokens/purge", id="token"),
    pytest.param(["mission-binding", "purge"], "candidates",
                 "/admin/api/mission-bindings/purge", id="mission-binding"),
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Rétention invalide → aucun appel réseau
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("base,_cle,_url", _PURGES)
@pytest.mark.parametrize("suffixe", [
    ["--older-than", "abc", "--yes"],     # non entier
    ["--older-than", "--yes"],            # `--yes` consommé comme valeur
    ["--older-than"],                     # option en fin de ligne
    ["--older-than", "1.5", "--yes"],     # décimale
])
def test_retention_invalide_naucun_appel(base, _cle, _url, suffixe):
    """
    FAIL-CLOSE : une rétention qu'on ne sait pas lire ne doit produire AUCUN
    appel — ni aperçu, ni purge. Purger sur une valeur devinée supprimerait des
    enregistrements que l'opérateur voulait conserver.
    """
    fake, resultat, _ = _run(base + suffixe, queue=[])
    assert fake.posts == [], f"appel émis malgré une rétention invalide : {fake.posts}"
    assert resultat.exit_code != 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. Aperçu en échec → jamais de purge effective
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("base,_cle,_url", _PURGES)
def test_apercu_en_echec_pas_de_purge(base, _cle, _url):
    """On ne supprime pas sur la foi d'un décompte qu'on n'a pas obtenu."""
    fake, _, _c = _run(base + ["--yes"], queue=[{"status": "error", "message": "boom"}])
    assert len(fake.posts) == 1, "plus d'un appel après un aperçu en échec"
    assert fake.posts[0]["dry_run"] is True
    assert not any(p.get("dry_run") is False for p in fake.posts)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Séquence nominale et rôle de --yes
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_yes_execute_apres_apercu_reussi(base, cle, url_attendue):
    """`--yes` ne saute pas l'aperçu : il saute la CONFIRMATION."""
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, cle: []},
        {"status": "ok", "count": 2, "older_than_days": 30, "purged": []},
    ])
    assert len(fake.posts) == 2
    assert fake.posts[0]["dry_run"] is True
    assert fake.posts[1]["dry_run"] is False
    # L'ENDPOINT compte autant que le payload : sans cette assertion, une purge
    # de tokens dirigée vers l'endpoint des bindings passait inaperçue (revue).
    assert fake.urls == [f"http://localhost:8085{url_attendue}"] * 2, fake.urls


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_sans_yes_refus_de_confirmation_pas_de_purge(base, cle, url_attendue):
    """
    Sans `--yes`, l'opérateur est interrogé. S'il refuse, RIEN n'est supprimé.

    C'est le test qui protège le geste le plus dangereux : une purge lancée par
    inadvertance et non confirmée. Il a d'abord été écrit avec un simulacre qui
    renvoyait `False` — et il ÉCHOUAIT, révélant que la valeur de retour n'est
    pas consultée : c'est `abort=True` qui interrompt, par exception.
    """
    fake, resultat, confirm = _run(base, queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, cle: []},
    ], confirme=False)
    assert len(fake.posts) == 1
    assert fake.posts[0]["dry_run"] is True
    assert resultat.exit_code != 0, "un refus doit interrompre la commande"

    # LE point du test : sans `abort=True`, Click renverrait False sur un refus,
    # valeur que l'appelant n'examine pas — la purge partirait quand même.
    assert confirm.appels, "aucune confirmation demandée avant une purge irréversible"
    assert all(a.get("abort") is True for a in confirm.appels), (
        f"click.confirm appelé sans abort=True : {confirm.appels}"
    )


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_dry_run_explicite_pas_de_purge(base, cle, url_attendue):
    """`--dry-run` s'arrête après l'aperçu, même combiné à `--yes`."""
    fake, _, _c = _run(base + ["--dry-run", "--yes"], queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, cle: []},
    ])
    assert len(fake.posts) == 1
    assert fake.posts[0]["dry_run"] is True


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_retention_par_defaut_est_trente_jours(base, cle, url_attendue):
    """
    RED sans garde : la rétention PAR DÉFAUT doit valoir 30 jours, à l'aperçu
    comme à la purge.

    Relevé en revue : sans ce test, passer le défaut de 30 à 0 laissait les 18
    autres verts. Une purge lancée sans `--older-than` aurait alors supprimé
    tout l'historique au lieu de conserver un mois.
    """
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": 1, "older_than_days": 30, cle: []},
        {"status": "ok", "count": 1, "older_than_days": 30, "purged": []},
    ])
    assert [p["older_than_days"] for p in fake.posts] == [30, 30]


@pytest.mark.parametrize("base,_cle,_url", _PURGES)
def test_retention_negative_refusee(base, _cle, _url):
    """
    RED : `type=int` acceptait `--older-than -1`. Avec la sémantique « purger ce
    qui est plus vieux que N jours », une valeur négative sélectionne TOUT et
    contourne la rétention demandée — l'inverse de l'intention.

    Dette préexistante relevée en revue, fermée ici : l'option est bornée à
    `>= 0`. Zéro reste accepté, c'est un choix explicite (« purger sans condition
    d'âge ») ; une valeur négative n'en est pas un.
    """
    fake, resultat, _ = _run(base + ["--older-than", "-1", "--yes"], queue=[])
    assert fake.posts == [], f"purge amorcée avec une rétention négative : {fake.posts}"
    assert resultat.exit_code != 0


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_apercu_vide_pas_de_purge(base, cle, url_attendue):
    """
    RED : un aperçu réussi mais VIDE ne doit déclencher aucune purge, même avec
    `--yes`. Sans ce test, neutraliser la garde `count == 0` laissait les 22
    autres verts — une requête destructive partait alors sur un ensemble vide.

    Le risque n'est pas théorique : entre l'aperçu et la purge, la fenêtre de
    rétention se déplace. Envoyer une purge « puisqu'il n'y a rien » revient à
    supprimer ce qui sera devenu éligible entre-temps.

    PORTÉE : cette garde ferme le cas VIDE, pas la fenêtre en général. La purge
    ne transmet que la durée de rétention et le serveur recalcule la sélection —
    fermer complètement demanderait que la purge porte l'empreinte de l'aperçu,
    ce qui relève du serveur. Limite documentée au CHANGELOG et dans le guide CLI.
    """
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": 0, "older_than_days": 30, cle: []},
    ])
    assert len(fake.posts) == 1, f"purge émise malgré un aperçu vide : {fake.posts}"
    assert fake.posts[0]["dry_run"] is True
    assert not any(p.get("dry_run") is False for p in fake.posts)


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
@pytest.mark.parametrize("decompte", [-1, True, "0", "2", None, 1.5])
def test_decompte_illisible_pas_de_purge(base, cle, url_attendue, decompte):
    """
    RED : la garde d'origine était `if n == 0`. Elle laissait passer `-1`, `True`
    (un booléen EST un entier en Python), `"0"` et `"2"` — quatre formes qui
    déclenchaient une suppression sur un aperçu qu'on n'avait pas su lire.

    Doctrine de sûreté d'état : une décision destructive se prend sur une PREUVE
    POSITIVE STRICTE, jamais sur un signal ambigu. Un décompte qui n'est pas un
    entier strictement positif n'est pas une preuve.
    """
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": decompte, "older_than_days": 30, cle: []},
    ])
    assert not any(p.get("dry_run") is False for p in fake.posts), (
        f"purge émise sur un décompte illisible ({decompte!r}) : {fake.posts}"
    )


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_echec_reseau_de_la_purge_pas_de_reprise(base, cle, url_attendue):
    """
    Une exception sur la purge NE DOIT PAS être suivie d'une reprise. Après un
    délai d'attente ambigu, la première requête peut déjà avoir été appliquée
    côté serveur : réessayer supprimerait une seconde fois, sur une sélection
    recalculée.

    Sans ce test, ajouter un `retry` dans le `except` passait inaperçu.
    """
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, cle: []},
    ], echec_au=2)
    assert len(fake.posts) == 2, f"nombre de tentatives inattendu : {fake.posts}"


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_authentification_transmise(base, cle, url_attendue):
    """
    Le bearer doit accompagner CHAQUE appel, aperçu comme purge. Sans cette
    assertion, retirer les en-têtes laissait les 22 tests verts : le serveur
    refuserait la requête, mais le contrat client ne serait plus vérifié.
    """
    fake, _, _c = _run(base + ["--yes"], queue=[
        {"status": "ok", "count": 1, "older_than_days": 30, cle: []},
        {"status": "ok", "count": 1, "older_than_days": 30, "purged": []},
    ])
    assert len(fake.headers) == 2
    for h in fake.headers:
        assert h.get("Authorization") == f"Bearer {_JETON_TEST}", h


@pytest.mark.parametrize("base,cle,url_attendue", _PURGES)
def test_retention_valide_propagee(base, cle, url_attendue):
    """La rétention saisie doit atteindre le serveur telle quelle, aperçu ET purge."""
    fake, _, _c = _run(base + ["--older-than", "7", "--yes"], queue=[
        {"status": "ok", "count": 1, "older_than_days": 7, cle: []},
        {"status": "ok", "count": 1, "older_than_days": 7, "purged": []},
    ])
    assert fake.posts[0]["older_than_days"] == 7
    assert fake.posts[1]["older_than_days"] == 7
    assert fake.posts[1]["dry_run"] is False
