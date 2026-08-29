"""#152 — une indisponibilité du JWKS n'est plus annoncée comme un jeton invalide.

Quand `secret_consume` ne peut pas vérifier l'identité de mission parce que le
service de clés est hors d'atteinte, il rendait `error_type: "jwt_invalid"`.

C'est la discipline #78 violée : fondre **un FAIT** sur l'appelant (« le jeton est
invalide ») et **une IGNORANCE** de notre côté (« nous n'avons pas pu le vérifier »)
sous un même nom.

⚠️ L'enjeu n'est pas cosmétique, et il vient de leur contrat, pas du nôtre.
`mcp-agent` traite tout `error_type` autre que `backend_unavailable` comme une
consommation INCERTAINE — donc secret condamné, et depuis leur lot #49 **arrêt
terminal de mission avec alerte de sécurité**. Sous `jwt_invalid`, une simple
indisponibilité de l'endpoint JWKS mono-instance de `mcp-mission` se lisait chez eux
comme un **incident d'intégrité de credential**.

Le refus précède tout effet OpenBao : `backend_unavailable` est donc à la fois
sémantiquement juste et conforme à la garantie que nous leur avons publiée.

⚠️ RECTIFICATION #154 — la rédaction d'origine de cette docstring affirmait que « ce
défaut n'est atteignable qu'en `ENFORCE=true` ; en production l'échec est journalisé
puis IGNORÉ et le déballage continue ». **C'était faux, et un test vert le
verrouillait** : l'assertion de résultat portait sur un mock qui rendait toujours `ok`.
Le déballage était bien TENTÉ, puis REFUSÉ en `not_found` — `mission_id` restant vide,
la clé composite ne correspondait à rien. Le correctif de #152 ne couvrait donc que le
chemin DORMANT. Voir `tests/test_indispo_hors_enforce_154.py`, qui mesure la chaîne
réelle sans mock de consommation.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def _run(coro):
    return asyncio.run(coro)


def _reglages(enforce: bool):
    return SimpleNamespace(
        enforce_mission_token_validation=enforce,
        mission_jwks_url="https://mission.interne/.well-known/jwks.json",
        mission_status_url="", mission_status_cache_ttl=0,
        mission_token_aud="mcp-vault:test:v1",
        resolved_mission_aud="mcp-vault:test:v1",
        mcp_component_kind="vault",
        mission_token_leeway_seconds=10,
    )


class _ValidateurQuiEchoue:
    """Double du validateur : lève l'erreur métier portant le motif voulu."""

    def __init__(self, motif: str):
        self._motif = motif

    def validate(self, jeton):
        from mcp_vault.auth.jwt_validator import MissionTokenError

        raise MissionTokenError(self._motif)


def _coroutine_qui_rend(valeur):
    async def _f(*a, **k):
        return valeur
    return _f


def _motifs_depuis_le_code() -> set:
    """Le vocabulaire COMPLET des motifs de `MissionTokenError`, lu dans le code.

    ⚠️ Jamais recopié à la main. Une liste manuelle avait omis sept motifs — dont
    `iat_future` et `component_id_mismatch` — et classer l'un d'eux en
    `backend_unavailable` n'aurait fait rougir aucun test.
    """
    import ast
    import pathlib

    from mcp_vault.auth import jwt_validator as jv

    motifs = set(jv._INVALID_REASON_MAP.values()) | set(jv._FORBIDDEN_REASON_MAP.values())
    # Les motifs levés DIRECTEMENT, sans passer par un dictionnaire.
    source = pathlib.Path(jv.__file__).read_text(encoding="utf-8")
    for noeud in ast.walk(ast.parse(source)):
        if (isinstance(noeud, ast.Call)
                and isinstance(noeud.func, ast.Name)
                and noeud.func.id == "MissionTokenError"
                and noeud.args
                and isinstance(noeud.args[0], ast.Constant)
                and isinstance(noeud.args[0].value, str)):
            motifs.add(noeud.args[0].value)
    # Préfixe dynamique traité à part dans `validate()` : un représentant suffit.
    motifs.add("missing_claim:tenant_id")
    return motifs


_TOUS_LES_MOTIFS = _motifs_depuis_le_code()


def _consommer_via_chaine_reelle(exception, enforce: bool):
    """Comme `_consommer`, mais l'erreur est levée par `validate_mission_token`.

    La traduction `_INVALID_REASON_MAP` est donc RÉELLEMENT exercée — ce que
    l'injection directe du motif final ne fait pas.
    """
    from mcp_vault import server as s
    from mcp_vault.auth.jwt_validator import MissionTokenValidator

    deballages = []

    async def faux_consume(*a, **k):
        deballages.append(1)
        return {"status": "ok", "secret": {"x": 1}}

    def valider_qui_leve(*a, **k):
        raise exception

    validateur = MissionTokenValidator.__new__(MissionTokenValidator)
    validateur._expected_aud = "mcp-vault:test:v1"
    validateur._leeway = 10
    validateur._jwks_url = "https://mission.interne/.well-known/jwks.json"
    validateur._jwks_cache = object()  # non None : `_get_cache` ne cherche rien
    validateur._component_kind = "vault"
    validateur._cache_ttl = 60

    with patch.object(s, "settings", _reglages(enforce)), \
         patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
         patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=None), \
         patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
               return_value=validateur), \
         patch("mcp_vault.auth.jwt_validator.validate_mission_token",
               new=valider_qui_leve), \
         patch("mcp_vault.vault.wrapping.consume_wrap_secret", new=faux_consume):
        res = _run(s.secret_consume(wrap_token="t", operation_id="op-1",
                                   mission_token="a.b.c"))
    return res, len(deballages)


def _consommer(motif: str, enforce: bool):
    """Exécute `secret_consume` avec un validateur qui échoue sur `motif`.

    Retourne (résultat, déballages_tentés) — le second compte les appels réels à
    `consume_wrap_secret`, pour prouver qu'un refus n'a RIEN tenté.
    """
    from mcp_vault import server as s

    deballages = []

    async def faux_consume(*a, **k):
        deballages.append(1)
        return {"status": "ok", "secret": {"x": 1}}

    with patch.object(s, "settings", _reglages(enforce)), \
         patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
         patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=None), \
         patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
               return_value=_ValidateurQuiEchoue(motif)), \
         patch("mcp_vault.vault.wrapping.consume_wrap_secret", new=faux_consume):
        res = _run(s.secret_consume(wrap_token="t", operation_id="op-1",
                                    mission_token="a.b.c"))
    return res, len(deballages)


# ── 1. Le correctif : l'ignorance porte son propre nom ──────────────────────


class TestUneIndisponibiliteDeCleNEstPasUnJetonInvalide:
    @pytest.mark.parametrize("motif", ["jwks_unavailable"])
    def test_le_service_de_cles_hors_d_atteinte_rend_backend_unavailable(self, motif):
        """Le cas franc : nous n'avons pas pu vérifier, et nous le disons."""
        res, deballages = _consommer(motif, enforce=True)

        assert res["status"] == "error"
        assert res["error_type"] == "backend_unavailable", (
            f"obtenu {res!r} — sous `jwt_invalid`, mcp-agent condamne le secret et "
            "arrête la mission avec une alerte de sécurité"
        )
        assert deballages == 0, "un déballage a été tenté malgré le refus"

    def test_le_refus_ne_reflete_PAS_le_motif_interne(self):
        """#78/D5 : le motif peut porter une valeur non vérifiée — il reste au log."""
        res, _ = _consommer("jwks_unavailable", enforce=True)

        assert "jwks" not in res["message"].lower()
        assert "jwks_unavailable" not in str(res)

    @pytest.mark.parametrize("motif", sorted(_TOUS_LES_MOTIFS - {"jwks_unavailable"}))
    def test_TOUT_LE_RESTE_garde_sa_classe(self, motif):
        """CONTRÔLE INDISPENSABLE : le correctif ne doit pas élargir
        `backend_unavailable`. Sa valeur pour les trois équipes vient de son
        ÉTROITESSE — « aucun effet tenté ». Un fourre-tout la détruirait.

        ⚠️ Les motifs sont **énumérés DEPUIS LE CODE** (`_INVALID_REASON_MAP`,
        `_FORBIDDEN_REASON_MAP`, et les levées directes), jamais recopiés à la main.
        Une première rédaction de ce test en listait sept ; la revue en a trouvé
        **sept autres manquants** — dont `iat_future`, `bad_mission_id`, `bad_jti`,
        `bad_tenant_id`, `bad_scope`, `validation_failed` et
        `component_id_mismatch`. Classer l'un d'eux en `backend_unavailable`
        n'aurait fait rougir aucun test.

        ⇒ Un motif ajouté plus tard au vocabulaire est **automatiquement couvert**.
        """
        attendu = "misconfigured" if motif == "misconfigured_expected_aud" else "jwt_invalid"
        res, deballages = _consommer(motif, enforce=True)

        assert res["error_type"] == attendu, (
            f"{motif} → {res['error_type']} (attendu {attendu}) : soit le mapping a "
            "élargi backend_unavailable, soit un motif a changé de classe"
        )
        assert deballages == 0

    def test_le_vocabulaire_enumere_couvre_bien_le_code(self):
        """Garde-fou de l'énumération elle-même : si elle devenait vide ou étriquée,
        le test ci-dessus passerait en n'éprouvant rien."""
        assert len(_TOUS_LES_MOTIFS) >= 15, (
            f"seulement {len(_TOUS_LES_MOTIFS)} motifs collectés — l'énumération "
            "depuis le code a cessé de fonctionner"
        )
        for indispensable in ("invalid_signature", "iat_future", "bad_scope",
                              "component_id_mismatch", "jwks_unavailable",
                              "misconfigured_expected_aud"):
            assert indispensable in _TOUS_LES_MOTIFS, indispensable

    def test_un_JWK_illisible_passe_par_la_CHAINE_REELLE(self):
        """⚠️ Relevé en revue : les autres cas injectent le motif final directement,
        donc le MAPPING `bad_jwk → jwks_unavailable` n'était pas éprouvé.

        Ici la chaîne complète est exercée : `validate_mission_token` lève
        `MissionTokenInvalid("bad_jwk")`, `_INVALID_REASON_MAP` le traduit, et
        `secret_consume` doit conclure à une indisponibilité. Changer cette entrée
        du mapping fait désormais rougir ce test.
        """
        from mcp_vault.auth.mission_jwt import MissionTokenInvalid

        res, deballages = _consommer_via_chaine_reelle(
            MissionTokenInvalid("bad_jwk"), enforce=True)

        assert res["error_type"] == "backend_unavailable", (
            f"obtenu {res!r} — un JWK illisible met la clé publique hors d'atteinte, "
            "ce n'est pas un jeton invalide"
        )
        assert deballages == 0

    def test_une_signature_invalide_passe_aussi_par_la_chaine_reelle(self):
        """CONTRÔLE de la chaîne : elle doit distinguer, pas tout convertir."""
        from mcp_vault.auth.mission_jwt import MissionTokenInvalid

        res, _ = _consommer_via_chaine_reelle(
            MissionTokenInvalid("bad_signature"), enforce=True)

        assert res["error_type"] == "jwt_invalid", (
            f"obtenu {res!r} — la chaîne réelle convertit tout en indisponibilité"
        )


# ── 2. La posture de production reste inchangée ─────────────────────────────


class TestSansEnforcementUnFaitSurLAppelantNEstPasOppose:
    """`ENFORCE=false` (posture de production jusqu'à #47) : un motif qui est un FAIT
    sur l'appelant — jeton forgé, périmé, `kid` inconnu — n'est pas opposé ici, et la
    consommation est TENTÉE.

    ⚠️ Cette classe s'appelait `TestSansEnforcementLaConduiteNeChangePas` et affirmait
    que « le déballage continue », avec `assert res["status"] == "ok"`. **Le `ok` venait
    du mock `faux_consume`, pas du code.** En réalité `mission_id` reste vide, donc la
    clé composite ne correspond à rien et le refus sort en `not_found` (#154). On ne
    prouve donc ICI que l'absence de court-circuit — le résultat réel se mesure sans
    mock dans `tests/test_indispo_hors_enforce_154.py`.

    ⚠️ `jwks_unavailable` a QUITTÉ cette liste : depuis #154 il court-circuite dans les
    DEUX postures, parce qu'il nomme notre incapacité et non un fait sur l'appelant.
    """

    @pytest.mark.parametrize("motif", [
        "invalid_signature", "kid_unknown_or_revoked", "token_expired",
    ])
    def test_l_echec_n_est_pas_oppose_et_la_consommation_est_TENTEE(self, motif):
        res, deballages = _consommer(motif, enforce=False)

        assert deballages == 1, (
            "sans enforcement, un fait sur l'appelant ne doit pas court-circuiter la "
            f"consommation ; obtenu {res!r}"
        )

    @pytest.mark.parametrize("motif", ["jwks_unavailable", "misconfigured_expected_aud"])
    def test_notre_INCAPACITE_court_circuite_meme_sans_enforcement(self, motif):
        """#154 : le hissage hors de la garde `enforce`. Le témoin est le compteur de
        déballages : il doit rester à ZÉRO, sinon rien n'a été court-circuité."""
        res, deballages = _consommer(motif, enforce=False)

        assert deballages == 0, (
            f"{motif} doit court-circuiter AVANT toute consommation ; obtenu {res!r}"
        )
        assert res["error_type"] != "not_found", (
            "un refus faute d'avoir pu vérifier ne doit jamais s'annoncer "
            f"« opération inconnue » ; obtenu {res!r}"
        )


# ── 3. Le recensement publié était FAUX — verrouillé ici ───────────────────


class TestSecretWrapNeValidePasDeJetonDeMission:
    """⚠️ Nous avons publié — README FR/EN, CHANGELOG, #148, #152 et deux messages
    aux équipes — que `secret_wrap` faisait partie des sites de validation du
    `mission_token`. **C'est faux.**

    L'erreur vient d'une INFÉRENCE : un `grep` sur
    `enforce_mission_token_validation` trouve un bloc dans `secret_wrap`, dont le
    commentaire mentionne `secret_consume`. Nous en avons conclu à un bloc de
    validation. C'en est un de **configuration** et de complétude de binding.

    Ce test verrouille le fait mesuré, pour qu'aucun recensement futur ne
    reproduise l'inférence.
    """

    def test_secret_wrap_n_a_pas_de_parametre_mission_token(self):
        import inspect

        from mcp_vault import server as s

        cible = getattr(s.secret_wrap, "fn", s.secret_wrap)  # tolère le décorateur MCP
        params = list(inspect.signature(cible).parameters)
        assert "mission_token" not in params, (
            f"`secret_wrap` prend désormais un mission_token ({params}) — le "
            "recensement des sites JWKS doit être refait, et #152 relue"
        )

    def test_secret_wrap_ne_TOUCHE_pas_le_cache_JWKS_a_l_execution(self):
        """⚠️ Version BEHAVIOURALE, après un finding de revue.

        La première rédaction cherchait des noms de fonctions dans le texte de
        `secret_wrap`. Contournable : un import aliasé, ou un validateur obtenu
        hors de la fonction puis appelé via `.validate(...)`, aurait laissé le test
        vert. On observe donc l'EXÉCUTION, pas la source.

        Les trois portes d'accès au cache JWKS sont instrumentées ; `secret_wrap`
        est réellement exécuté en mode enforced — la posture la plus susceptible de
        déclencher une validation — et aucune ne doit être franchie.
        """
        from mcp_vault import server as s

        acces = []

        def porte(nom):
            def _f(*a, **k):
                acces.append(nom)
                return None
            return _f

        async def faux_wrap(*a, **k):
            return {"status": "ok", "wrap_token": "x", "secret_id": "s"}

        with patch.object(s, "settings", _reglages(enforce=True)), \
             patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
             patch("mcp_vault.auth.mission_jwt.get_jwks_cache",
                   new=porte("get_jwks_cache")), \
             patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
                   new=porte("get_mission_token_validator")), \
             patch("mcp_vault.auth.mission_jwt.validate_mission_token",
                   new=porte("validate_mission_token")), \
             patch("mcp_vault.auth.context.check_wrap_permission", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_path_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_wrap_path_policy", return_value=None), \
             patch("mcp_vault.vault.wrapping.wrap_secret", new=faux_wrap):
            res = _run(s.secret_wrap(
                vault_id="v", secret_path="p", mission_id="m1",
                operation_id="op-1", tenant_id="t1",
                expected_aud="mcp-vault:test:v1",
            ))

        assert res.get("status") == "ok", (
            f"le scénario n'a pas atteint la création — il ne prouve rien : {res!r}"
        )
        assert acces == [], (
            f"`secret_wrap` a touché le cache JWKS ({acces}) : il devient un site "
            "JWKS, donc soumis au déport de #148 ET au mapping de #152"
        )
