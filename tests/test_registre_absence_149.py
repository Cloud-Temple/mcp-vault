"""#149 — le registre wrap ne déduit plus une absence du TEXTE d'une erreur.

Avant ce lot, `WrapRegistry.load()` concluait « objet absent » dès que le message
d'erreur CONTENAIT « 404 » ou « NoSuchKey ». Le registre repartait alors vide **en
se déclarant fiable**, le garde-fou fail-close de v0.15.0 ne voyait rien, et une
clé de provisionnement déjà engagée paraissait vierge — le trou de rejeu fermé en
v0.13.0 puis verrouillé en v0.14.0.

La règle appliquée ici est celle de la revue Codex #69 (BLOQUANT-2), que les trois
magasins d'autorisation portent depuis et que le registre n'avait jamais reçue.

⚠️ Chaque cas VERT de ce fichier exige un fait POSITIF observable (drapeau, entrée
conservée, sauvegarde comptée). Un test qui se contenterait d'un refus passerait
dans un monde où tout est refusé.
"""

import asyncio
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _run(coro):
    return asyncio.run(coro)


def _erreur_client(code: str, message: str = "boom"):
    """Un vrai `botocore.ClientError` portant le code structuré demandé."""
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": message}}, "GetObject")


def _reglages():
    return SimpleNamespace(s3_bucket_name="b")


def _registre(entrees=()):
    from mcp_vault.vault.wrapping import WrapRegistry

    registre = WrapRegistry(_reglages())
    registre._wraps = list(entrees)
    return registre


def _entree_bloquante(operation_id="op-1", mission_id="m1"):
    return {"operation_id": operation_id, "mission_id": mission_id, "status": "active"}


def _s3_qui_leve(erreur):
    client = MagicMock()
    client.get_object.side_effect = erreur
    return client


def _s3_qui_rend(corps: bytes):
    """Un GET qui RÉUSSIT et renvoie ce corps — aucune erreur à classer."""
    client = MagicMock()
    client.get_object.return_value = {"Body": io.BytesIO(corps)}
    return client


class Config:
    """Réglages minimaux de `wrap_secret` — aucun appel réseau attendu."""

    openbao_addr = "http://localhost:8200"
    wrap_default_ttl_seconds = 300
    wrap_max_ttl_seconds = 600


# ── 1. Le classement de l'absence ────────────────────────────────────────────


class TestLAbsenceEstUnFaitStructure:
    def test_un_NoSuchKey_authentique_vaut_TOUJOURS_registre_vide(self):
        """CONTRÔLE INDISPENSABLE : le premier démarrage doit rester nominal.

        Un correctif qui refuserait aussi l'absence légitime tuerait le guichet de
        credentials sur tout déploiement neuf — le fichier registre n'est créé par
        personne, il naît de la première écriture.
        """
        registre = _registre([_entree_bloquante()])
        registre._get_s3_data = MagicMock(
            return_value=_s3_qui_leve(_erreur_client("NoSuchKey"))
        )

        registre.load()

        assert registre._wraps == [], "une absence authentique doit vider l'instantané"
        assert registre._last_load_ok is True, (
            "l'absence nominale est un FAIT connu, pas une panne — la refuser "
            "rendrait le premier démarrage impossible"
        )
        assert not registre.freshness.last_error, "une absence nominale n'est pas une erreur"

    def test_un_404_generique_ne_vaut_PAS_registre_vide(self):
        """Le défaut de #149, dans sa forme exacte observée le 16/08/2026.

        Le faux S3 du banc plateforme renvoyait `404` au lieu de `NoSuchKey`. Les
        trois magasins stricts ont refusé ; le registre, lui, est passé.
        """
        entree = _entree_bloquante()
        registre = _registre([entree])
        registre._get_s3_data = MagicMock(
            return_value=_s3_qui_leve(_erreur_client("404", "Not Found"))
        )

        registre.load()

        assert registre._last_load_ok is False, (
            "un 404 générique s'est fait passer pour une absence — le registre se "
            "déclare fiable alors qu'il ne sait rien"
        )
        assert registre._wraps == [entree], (
            "l'instantané mémoire a été ÉCRASÉ par une panne : les clés déjà "
            "engagées redeviennent vierges sans aucune perte de donnée réelle"
        )
        assert registre.freshness.last_error, (
            "la panne doit être NOMMÉE : sans elle, la sonde ne signale rien"
        )

    @pytest.mark.parametrize(
        "erreur, pourquoi",
        [
            (
                _erreur_client("InternalError", "500 (request-id: abc404def)"),
                "un identifiant de requête contenant 404",
            ),
            (
                _erreur_client("SlowDown", "throttled, retry (NoSuchKey unrelated)"),
                "le motif NoSuchKey présent hors du champ structuré",
            ),
            (
                _erreur_client("NoSuchBucket", "bucket absent"),
                "un bucket absent n'est pas un objet absent",
            ),
            (_erreur_client("AccessDenied", "403"), "un refus d'accès"),
            (
                ConnectionError("connexion refusée sur 10.0.0.1:404"),
                "un port contenant 404, hors botocore",
            ),
            (Exception("NoSuchKey"), "une exception nue au message trompeur"),
        ],
    )
    def test_le_TEXTE_de_l_erreur_ne_decide_jamais(self, erreur, pourquoi):
        """Anti-régression directe sur `"404" in str(e)`.

        Chacun de ces cas passait AVANT ce lot pour « fichier absent ».
        """
        registre = _registre([_entree_bloquante()])
        registre._get_s3_data = MagicMock(return_value=_s3_qui_leve(erreur))

        registre.load()

        assert registre._last_load_ok is False, f"{pourquoi} → classé comme absence"

    def test_le_predicat_partage_classe_correctement(self):
        """La règle #69, en un seul endroit désormais (`s3_client.objet_absent`)."""
        from mcp_vault.s3_client import objet_absent

        assert objet_absent(_erreur_client("NoSuchKey")) is True
        for erreur in (
            _erreur_client("404"),
            _erreur_client("NotFound"),
            _erreur_client("NoSuchBucket"),
            _erreur_client("InternalError", "req-404"),
            Exception("404 NoSuchKey"),
            ConnectionError("10.0.0.1:404"),
        ):
            assert objet_absent(erreur) is False, f"{erreur!r} classé comme absence"


class TestLaRegleNePeutPlusEtreOUBLIEE:
    """#149 est né d'une règle **recopiée** dans trois magasins et absente du
    quatrième. Un test qui énumère les magasins connus ne protège donc pas du
    scénario qui a produit le défaut : un magasin de PLUS, écrit plus tard, sans
    la règle.

    Ces deux tests portent sur une propriété de l'ARBRE SOURCE, pas sur une liste
    de classes. Ils couvrent donc aussi le magasin qui n'existe pas encore.
    """

    def _sources(self):
        import pathlib

        racine = pathlib.Path(__file__).resolve().parent.parent / "src"
        return sorted(racine.rglob("*.py"))

    def test_aucun_fichier_ne_deduit_l_absence_d_une_SOUS_CHAINE(self):
        """Interdit le retour du motif `"NoSuchKey" in str(...)`.

        Deux occurrences existaient encore avant ce lot : le registre wrap
        (#149, rejeu de clé possible) et le téléchargement des clés d'unseal
        (diagnostic faux — « clés introuvables » sur une panne de stockage).

        ⚠️ La règle est écrite À L'ENVERS : on interdit le motif partout, au lieu
        d'autoriser les fichiers qu'on connaît. Une liste blanche laisserait
        passer le prochain fichier.
        """
        coupables = []
        for chemin in self._sources():
            for numero, ligne in enumerate(
                chemin.read_text(encoding="utf-8").splitlines(), start=1
            ):
                nu = ligne.strip()
                # Les docstrings et commentaires CITENT le motif pour l'interdire.
                if nu.startswith("#") or nu.startswith("*") or nu.startswith(">"):
                    continue
                if '"NoSuchKey" in str(' in ligne or "'NoSuchKey' in str(" in ligne:
                    coupables.append(f"{chemin.name}:{numero}")

        assert not coupables, (
            "test d'absence par sous-chaîne réintroduit — utiliser "
            f"`s3_client.objet_absent` : {coupables}"
        )

    def test_le_predicat_partage_n_a_qu_UNE_definition(self):
        """Verrouille l'unicité de la source.

        Si quelqu'un recopie la fonction plutôt que de l'importer, la divergence
        redevient possible — c'est exactement le mécanisme de #149.
        """
        import ast
        import pathlib

        definitions = []
        for chemin in self._sources():
            arbre = ast.parse(chemin.read_text(encoding="utf-8"))
            for noeud in ast.walk(arbre):
                if isinstance(noeud, ast.FunctionDef) and noeud.name in (
                    "objet_absent",
                    "_is_missing_key_error",
                ):
                    definitions.append(f"{chemin.name}:{noeud.lineno} {noeud.name}")

        assert len(definitions) == 1, (
            f"le prédicat d'absence est défini {len(definitions)} fois : {definitions}"
        )
        assert definitions[0].startswith("s3_client.py"), definitions


# ── 1 bis. La seconde porte : un document valide mais faux ───────────────────


class TestUnDocumentCasseNEstPasUnRegistreVide:
    """Trouvé en revue adversariale — le correctif initial ne fermait qu'une porte.

    `load()` faisait `data.get("wraps", [])` : un GET qui RÉUSSIT en renvoyant un
    JSON valide sans la clé `wraps` produisait le même effet que le test par
    sous-chaîne — instantané vide, déclaré fiable — **sans même qu'une erreur soit
    levée**. C'est la seconde moitié de la règle #69, que `PolicyStore` porte
    depuis : « un objet sans cette clé, ou `{}` tout court, n'est PAS traité comme
    un store vide ».
    """

    @pytest.mark.parametrize(
        "corps, pourquoi",
        [
            (b"{}", "objet sans la clé wraps — un corps tronqué ou de remplacement"),
            (b'{"wraps": null}', "clé présente, valeur nulle"),
            (b'{"wraps": {}}', "clé présente, mauvais type"),
            (b'{"wraps": "op-1"}', "clé présente, chaîne au lieu d'une liste"),
            (b"[]", "liste à la racine au lieu de l'objet attendu"),
            (b'"registre"', "chaîne JSON valide à la racine"),
            (b'{"Wraps": []}', "casse différente — ce n'est pas notre schéma"),
        ],
    )
    def test_un_document_de_forme_cassee_est_une_PANNE(self, corps, pourquoi):
        entree = _entree_bloquante()
        registre = _registre([entree])
        registre._get_s3_data = MagicMock(return_value=_s3_qui_rend(corps))

        registre.load()

        assert registre._last_load_ok is False, f"{pourquoi} → pris pour un registre vide"
        assert registre._wraps == [entree], (
            "l'instantané mémoire a été écrasé : la validation doit précéder toute "
            "mutation d'état"
        )

    def test_CONTROLE_un_registre_legitimement_vide_reste_lisible(self):
        """`{"wraps": []}` est l'état RÉEL du fichier après une première écriture
        sans entrée. Le refuser casserait le cas nominal."""
        registre = _registre([_entree_bloquante()])
        registre._get_s3_data = MagicMock(return_value=_s3_qui_rend(b'{"wraps": []}'))

        registre.load()

        assert registre._wraps == []
        assert registre._last_load_ok is True, "un registre vide LÉGITIME doit se charger"

    def test_CONTROLE_un_document_conforme_charge_ses_entrees(self):
        entree = _entree_bloquante("op-9", "m9")
        registre = _registre()
        registre._get_s3_data = MagicMock(
            return_value=_s3_qui_rend(json.dumps({"wraps": [entree]}).encode())
        )

        registre.load()

        assert registre._wraps == [entree]
        assert registre._last_load_ok is True


# ── 2. La conséquence de sécurité ────────────────────────────────────────────


class TestUneCleEngageeResteRefusee:
    """Le point d'arrivée : ce que le défaut permettait réellement.

    La garantie publiée à `mcp-mission` est « une clé de provisionnement est à
    usage unique, SANS CONDITION ». Elle ne vaut que ce que vaut l'instantané que
    la garde interroge.
    """

    def _tenter_creation(self, registre):
        from mcp_vault.vault import wrapping as w

        client = MagicMock()
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=Config()):
            res = _run(
                w.wrap_secret(
                    vault_id="v", secret_path="p", mission_id="m1", operation_id="op-1"
                )
            )
        return res, client

    def test_le_rejeu_est_refuse_apres_une_erreur_mal_classable(self):
        """La chaîne complète du défaut, jouée de bout en bout."""
        registre = _registre([_entree_bloquante("op-1", "m1")])
        registre.sauvegardes = 0
        registre._save = lambda *a, **k: (
            setattr(registre, "sauvegardes", registre.sauvegardes + 1) or True
        )
        registre._get_s3_data = MagicMock(
            return_value=_s3_qui_leve(_erreur_client("404", "Not Found"))
        )
        registre.load()  # la lecture échoue de façon ambiguë

        res, client = self._tenter_creation(registre)

        assert res["status"] == "error", res
        assert res["error_type"] == "backend_unavailable", (
            f"refus attendu sur instantané non fiable, obtenu {res!r}"
        )
        assert registre.sauvegardes == 0, "une intention a été écrite sur un état incertain"
        assert not client.write.called, "OpenBao appelé alors que la clé pouvait être engagée"

    def test_le_rejeu_est_refuse_sur_un_document_valide_mais_casse(self):
        """La reproduction exacte du finding de revue : un GET qui réussit en
        renvoyant `{}` faisait répondre `ok` à `wrap_secret`, OpenBao appelé,
        sur une clé déjà engagée."""
        registre = _registre([_entree_bloquante("op-1", "m1")])
        registre.sauvegardes = 0
        registre._save = lambda *a, **k: (
            setattr(registre, "sauvegardes", registre.sauvegardes + 1) or True
        )
        registre._get_s3_data = MagicMock(return_value=_s3_qui_rend(b"{}"))
        registre.load()

        res, client = self._tenter_creation(registre)

        assert res["error_type"] == "backend_unavailable", (
            f"un document cassé a laissé recréer un secret : {res!r}"
        )
        assert registre.sauvegardes == 0
        assert not client.read.called and not client.write.called, (
            "OpenBao appelé alors que le registre ne savait rien de fiable"
        )

    def test_CONTROLE_une_cle_vierge_passe_toujours_la_garde(self):
        """Sans ce contrôle, le test précédent passerait dans un monde où TOUT est
        refusé — c'est-à-dire si le correctif avait tué le guichet.

        L'assertion est POSITIVE : l'intention doit être écrite (write-ahead), ce
        qui prouve que la garde a été franchie.
        """
        registre = _registre()
        registre.sauvegardes = 0
        registre._save = lambda *a, **k: (
            setattr(registre, "sauvegardes", registre.sauvegardes + 1) or True
        )
        registre._get_s3_data = MagicMock(
            return_value=_s3_qui_leve(_erreur_client("NoSuchKey"))
        )
        registre.load()  # absence légitime : registre vide ET fiable

        res, _ = self._tenter_creation(registre)

        assert registre._last_load_ok is True
        assert res.get("error_type") != "backend_unavailable", (
            f"la garde refuse une clé vierge sur un registre sain : {res!r}"
        )
        assert registre.sauvegardes >= 1, (
            "aucune intention écrite : la garde a bloqué avant le write-ahead, "
            "donc le cas nominal ne s'exécute plus"
        )


# ── 3. La volumétrie, mesurée sans devenir une cause (#146) ──────────────────


class TestVolumetrieDuRegistre:
    def test_la_cardinalite_est_gratuite_et_exacte(self):
        registre = _registre([_entree_bloquante(f"op-{i}") for i in range(7)])
        assert registre.volumetrie()["entries"] == 7

    def test_le_poids_est_releve_A_L_ECRITURE_et_pas_avant(self):
        registre = _registre([_entree_bloquante()])
        assert registre.volumetrie()["last_write_bytes"] is None, (
            "None = aucune écriture depuis le démarrage ; ce n'est pas « vide »"
        )

        registre._get_s3_data = MagicMock(return_value=MagicMock())
        assert registre._save() is True

        poids = registre.volumetrie()["last_write_bytes"]
        attendu = len(json.dumps({"wraps": registre._wraps}, indent=2, default=str).encode())
        assert poids == attendu, f"{poids} != {attendu}"

    def test_la_sonde_ne_SERIALISE_JAMAIS_le_registre(self):
        """Verrouille la raison d'être du relevé-à-l'écriture.

        Calculer la taille à la demande ferait sérialiser tout le registre à
        chaque appel de supervision : la sonde qui mesure le problème de
        volumétrie de #146 en deviendrait une cause. Le compteur ci-dessous ne
        peut pas rester à zéro par accident — le second appel prouve qu'il compte.
        """
        from mcp_vault.vault import wrapping as w

        registre = _registre([_entree_bloquante(f"op-{i}") for i in range(50)])
        appels = []
        vrai_dumps = json.dumps

        def dumps_compte(*a, **k):
            appels.append(1)
            return vrai_dumps(*a, **k)

        with patch.object(w.json, "dumps", dumps_compte):
            registre.volumetrie()
            assert appels == [], "la sonde a sérialisé le registre"
            # Le compteur EST branché : une écriture, elle, doit sérialiser.
            registre._get_s3_data = MagicMock(return_value=MagicMock())
            registre._save()
            assert appels, "le compteur ne mesure rien — le test précédent ne prouve rien"

    def test_la_sonde_de_fraicheur_publie_la_volumetrie(self, monkeypatch):
        """Le câblage : sans lui, la mesure existe mais n'atteint personne."""
        import mcp_vault.store_refresh as sr

        registre = _registre([_entree_bloquante(f"op-{i}") for i in range(3)])
        registre.freshness.mark_success()
        monkeypatch.setattr(sr, "_magasins", lambda: [("wrap_registry", registre)])

        vue = sr.freshness_report()["wrap_registry"]

        assert vue["entries"] == 3
        assert "last_write_bytes" in vue
        assert "stale" in vue, "la volumétrie ne doit pas écraser la fraîcheur"

    def test_un_magasin_sans_volumetrie_reste_publie(self, monkeypatch):
        """Les trois magasins d'autorisation n'exposent rien : la sonde ne doit
        ni planter ni les omettre."""
        import mcp_vault.store_refresh as sr
        from mcp_vault.auth.policies import PolicyStore

        magasin = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        magasin.freshness.mark_success()
        monkeypatch.setattr(sr, "_magasins", lambda: [("policy", magasin)])

        vue = sr.freshness_report()["policy"]

        assert "entries" not in vue
        assert "stale" in vue
