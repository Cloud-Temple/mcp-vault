"""#154 — en production, une indisponibilité du service de clés s'annonçait
« opération inconnue ».

Le correctif de #152 (`jwks_unavailable → backend_unavailable`) vivait **sous la garde
`if enforce:`**. Or la production tourne `ENFORCE_MISSION_TOKEN_VALIDATION=false` : le
chemin corrigé était DORMANT et le chemin VIVANT ne l'était pas.

Mécanisme mesuré : la validation échoue, `mission_id` reste **vide**, la clé composite
`(operation_id, "")` ne correspond à aucune entrée, et le refus sort en **`not_found`**
— « opération inconnue ou expirée ». Un fait POSITIF et FAUX sur l'appelant, qui envoie
chercher un défaut de provisionnement inexistant. `mcp-agent` lisant tout `error_type`
autre que `backend_unavailable` en consommation incertaine (leur #135), une
indisponibilité du JWKS mono-instance de `mcp-mission` produisait chez eux une **fausse
alerte de sécurité et un arrêt terminal de mission** (leur #49).

⚠️ POURQUOI CE FICHIER EXISTE, ET PAS SEULEMENT UN CAS DE PLUS DANS #152.
Le défaut avait survécu parce que le test qui « couvrait » la posture de production
mockait `consume_wrap_secret` par une fonction rendant TOUJOURS `{"status": "ok"}`. Le
vert venait du mock. **Ici, aucun mock de consommation** : registre réel contenant une
entrée `active`, vrai `consume_wrap_secret`, seul le validateur est doublé. Et un
TÉMOIN vérifie que ce banc sait aboutir — sans lui, un refus prouverait seulement que le
harnais est cassé.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Source unique du vocabulaire des motifs : la dérivation AST de #152, jamais une
# liste recopiée (une liste manuelle y avait omis sept motifs). `tests/` n'est pas un
# paquet et n'est pas sur `sys.path` — on l'ajoute ici plutôt que de dupliquer la
# dérivation, pour que le vocabulaire n'ait qu'un seul endroit d'où venir.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_mapping_jwks_152 import _motifs_depuis_le_code  # noqa: E402

MISSION_REELLE = "mis_cbd8f9e745ebf1899ab565db"
OP = "op-154"

# Les motifs qui nomment NOTRE incapacité — hissés hors de la garde `enforce` (#154).
NOTRE_INCAPACITE = {"jwks_unavailable", "misconfigured_expected_aud"}


def _reglages(enforce: bool):
    return SimpleNamespace(
        enforce_mission_token_validation=enforce,
        mission_jwks_url="https://mission.interne/.well-known/jwks.json",
        mission_status_url="", mission_status_cache_ttl=0,
        mission_token_aud="mcp-vault:test:v1",
        resolved_mission_aud="mcp-vault:test:v1",
        mcp_component_kind="vault", mission_token_leeway_seconds=10,
    )


def _registre_avec_une_entree_active():
    """Un registre RÉEL portant une entrée telle que `secret_wrap` l'écrit."""
    from mcp_vault.store_refresh import Freshness
    from mcp_vault.vault.wrapping import WrapRegistry

    class _Reg(WrapRegistry):
        def __init__(self):
            self._wraps = [{
                "operation_id": OP, "accessor": "ACC",
                "mission_id": MISSION_REELLE,
                "vault_id": "v", "secret_path": "p",
                "created_at": "2026-08-17T21:33:00+00:00", "expires_at": "",
                "status": "active", "tenant_id": "", "expected_aud": "",
            }]
            self.freshness = Freshness()
            self.freshness.mark_success()
            self._last_load_ok = True
            self.refresh_lock = asyncio.Lock()

        def load(self):
            pass

        def _save(self):
            return True

    return _Reg()


class _ValidateurQuiEchoue:
    def __init__(self, motif):
        self._motif = motif

    def validate(self, jeton):
        from mcp_vault.auth.jwt_validator import MissionTokenError
        raise MissionTokenError(self._motif)


class _ValidateurQuiPasse:
    """Le TÉMOIN : rend les claims d'un jeton réellement vérifié."""

    def validate(self, jeton):
        return {"mission_id": MISSION_REELLE, "tenant_id": ""}


def _mesurer(validateur, enforce: bool):
    """Exécute `secret_consume` de bout en bout. Rend (résultat, état de l'entrée)."""
    import sys as _sys

    from mcp_vault import server as s

    reg = _registre_avec_une_entree_active()
    mock_hvac = MagicMock()
    ephemere = MagicMock()
    mock_hvac.Client.return_value = ephemere
    ephemere.sys.unwrap.return_value = {"data": {"data": {"k": "v"}, "metadata": {}}}
    cfg = MagicMock()
    cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch.dict(_sys.modules, {"hvac": mock_hvac}), \
         patch.object(s, "settings", _reglages(enforce)), \
         patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
         patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=None), \
         patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
               return_value=validateur), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=MagicMock()), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        res = asyncio.run(s.secret_consume(wrap_token="wt", operation_id=OP,
                                          mission_token="a.b.c"))
    return res, reg._wraps[0]["status"]


# ── 0. Le témoin — sans lui, aucun refus ne prouve rien ─────────────────────


class TestLeBancSaitAboutir:
    """⚠️ GARDE ANTI-TEST-CREUX. Le défaut de #154 a survécu à un test vert dont le
    résultat venait d'un mock. Si ce témoin échoue, toutes les assertions de refus de
    ce fichier ne mesurent qu'un harnais cassé — pas un comportement."""

    def test_un_jeton_VERIFIE_consomme_reellement_l_enveloppe(self):
        res, statut = _mesurer(_ValidateurQuiPasse(), enforce=False)

        assert res["status"] == "ok", f"le banc ne sait pas aboutir : {res!r}"
        assert statut == "consumed", (
            "l'entrée doit passer active → consumed, sinon la vraie consommation "
            f"n'a pas été exercée ; obtenu {statut!r}"
        )


# ── 1. Le défaut : notre ignorance annoncée comme un fait sur l'appelant ────


class TestUneIndisponibiliteNEstPasUneOperationInconnue:
    def test_en_production_le_refus_est_backend_unavailable(self):
        """`ENFORCE=false` — la posture de `vault-01`. C'est LE cas du défaut."""
        res, statut = _mesurer(_ValidateurQuiEchoue("jwks_unavailable"), enforce=False)

        assert res["status"] == "error", (
            "l'enveloppe doit être cohérente avec le type d'erreur — un status « ok » "
            f"porteur d'un error_type serait illisible pour l'appelant ; {res!r}"
        )
        assert res["error_type"] == "backend_unavailable", (
            "en production, une indisponibilité du service de clés doit s'annoncer "
            f"comme telle et non « opération inconnue » ; obtenu {res!r}"
        )
        assert statut == "active", (
            "aucun déballage ne doit avoir été tenté — l'enveloppe reste intacte et "
            f"re-tentable ; entrée passée à {statut!r}"
        )

    def test_le_message_n_affirme_rien_sur_l_operation_de_l_appelant(self):
        res, _ = _mesurer(_ValidateurQuiEchoue("jwks_unavailable"), enforce=False)
        message = res["message"].lower()

        for mensonge in ("introuvable", "inconnue", "expirée"):
            assert mensonge not in message, (
                f"le message impute un défaut à l'appelant (« {mensonge} ») alors que "
                f"c'est NOTRE vérification qui a échoué : {res['message']!r}"
            )

    @pytest.mark.parametrize("enforce", [False, True])
    def test_les_DEUX_postures_rendent_le_meme_code(self, enforce):
        """Le hissage : `enforce` arbitre si un jeton INVALIDE est fatal, il n'arbitre
        pas si nous disons la vérité sur le motif du refus."""
        res, _ = _mesurer(_ValidateurQuiEchoue("jwks_unavailable"), enforce=enforce)

        assert res["error_type"] == "backend_unavailable", (
            f"ENFORCE={enforce} ne doit pas changer le NOM du refus ; obtenu {res!r}"
        )

    def test_une_misconfiguration_de_notre_audience_ne_blame_pas_l_appelant(self):
        res, statut = _mesurer(_ValidateurQuiEchoue("misconfigured_expected_aud"),
                               enforce=False)

        assert res["status"] == "error"
        assert res["error_type"] == "misconfigured", (
            "notre audience non résolue est NOTRE défaut de configuration, pas une "
            f"opération inconnue ; obtenu {res!r}"
        )
        assert statut == "active"


# ── 2. L'étroitesse : `backend_unavailable` ne devient pas un fourre-tout ───


class TestLEtroitesseEstPreserveeSansEnforcement:
    """#152 vérifiait l'étroitesse sous `enforce=True`. Le défaut de #154 vivait sous
    `enforce=False` : c'est donc LÀ qu'il faut la vérifier aussi.

    ⚠️ Vocabulaire énuméré DEPUIS LE CODE (dérivation AST de #152). Un motif ajouté
    plus tard entre automatiquement dans ce contrôle.
    """

    @pytest.mark.parametrize("motif", sorted(_motifs_depuis_le_code() - NOTRE_INCAPACITE))
    def test_aucun_autre_motif_ne_devient_backend_unavailable(self, motif):
        res, _ = _mesurer(_ValidateurQuiEchoue(motif), enforce=False)

        assert res["error_type"] != "backend_unavailable", (
            f"{motif!r} n'exprime pas notre incapacité — le ranger en "
            f"backend_unavailable ferait de cette classe un fourre-tout, et "
            f"`mcp-agent` re-tenterait un refus définitif ; obtenu {res!r}"
        )
        # ⚠️ On NE verrouille PAS la valeur exacte (`not_found` aujourd'hui). Elle est
        # une imperfection connue de la posture `ENFORCE=false`, laissée à #47 :
        # figer `== "not_found"` ferait rougir #47 et inviterait à corriger le test
        # plutôt que le code.

    def test_le_vocabulaire_controle_n_est_pas_vide(self):
        """Sans cette garde, une dérivation AST cassée rendrait la classe ci-dessus
        vide — et donc verte sans rien exercer."""
        restants = _motifs_depuis_le_code() - NOTRE_INCAPACITE
        assert len(restants) >= 15, (
            f"vocabulaire suspect ({len(restants)} motifs) — la dérivation depuis le "
            "code est probablement cassée"
        )


# ── 3. La PRÉMISSE du correctif : court-circuiter ne retire aucun succès ────


class TestLeCourtCircuitNeSupprimeAucunSuccesPossible:
    """Le correctif se justifie par un fait : la recherche par clé composite avec un
    `mission_id` vide ne pouvait **jamais** aboutir. Si cette prémisse tombe, le
    court-circuit devient une régression — ces tests la verrouillent.
    """

    def test_secret_wrap_REFUSE_un_mission_id_vide(self):
        """Donc aucune entrée du registre ne peut porter un `mission_id` vide."""
        from mcp_vault.vault.wrapping import _validate_inputs

        erreur = _validate_inputs("v", "chemin/ok", "", OP)

        assert erreur is not None and "mission_id" in erreur, (
            "si un mission_id vide devenait acceptable, une entrée vide existerait et "
            f"le court-circuit de #154 masquerait un succès possible ; obtenu {erreur!r}"
        )

    def test_la_cle_composite_vide_ne_correspond_a_aucune_entree_reelle(self):
        """Comportemental : le vrai registre, la vraie méthode de sélection."""
        reg = _registre_avec_une_entree_active()

        assert reg.get_by_composite_key(OP, "") is None, (
            "un mission_id vide ne doit correspondre à aucune entrée (égalité "
            "stricte, aucun joker)"
        )
        assert reg.get_by_composite_key(OP, MISSION_REELLE) is not None, (
            "témoin : la même recherche avec le vrai mission_id doit aboutir, sinon "
            "l'assertion ci-dessus ne prouve rien"
        )


# ── 4. Revue adversariale — le validateur absent est AUSSI notre incapacité ──


class TestLeValidateurNonInitialiseEstNotreIncapacite:
    """Trouvaille de revue. Le hissage du motif `jwks_unavailable` laissait derrière
    lui sa branche SŒUR : `validator is None` (lifecycle échoué, ou `MISSION_JWKS_URL`
    ajoutée à chaud). Sous `ENFORCE=false`, elle journalisait puis continuait avec un
    `mission_id` vide ⇒ `not_found`.

    ⚠️ C'est exactement l'erreur que ce lot corrige, commise en le corrigeant : lire
    une branche sans lire ce qui l'entoure. Et le cas est PLUS probable que la panne
    JWKS, puisqu'il découle d'un échec de démarrage — donc persistant.
    """

    def test_en_production_un_validateur_absent_refuse_sans_blamer_l_appelant(self):
        res, statut = _mesurer(None, enforce=False)

        assert res["status"] == "error"
        assert res["error_type"] == "misconfigured", (
            "un validateur non initialisé est NOTRE panne de démarrage, pas une "
            f"opération inconnue ; obtenu {res!r}"
        )
        assert statut == "active", (
            f"aucun déballage ne doit avoir été tenté ; entrée passée à {statut!r}"
        )

    def test_ce_refus_n_est_PAS_retentable(self):
        """`misconfigured` et non `backend_unavailable` : la condition exige un
        redémarrage après correction. Annoncer une classe que `mcp-agent` re-tente
        (leur #135) le ferait boucler sur un état qui ne se résout pas seul."""
        res, _ = _mesurer(None, enforce=False)

        assert res["error_type"] != "backend_unavailable", (
            "une panne persistante ne doit pas s'annoncer re-tentable ; "
            f"obtenu {res!r}"
        )


# ── 5. Revue adversariale — un kid inconnu PENDANT une panne du JWKS ────────


class TestUnKidInconnuPendantUnePanneNEstPasUnJetonForge:
    """Trouvaille de revue, mesurée dans `JWKSCache.get_key` : un `kid` absent
    déclenche un refresh forcé, et l'échec de ce refresh était **avalé** — le refus
    sortait ensuite en `unknown_kid`, « jeton non authentique ». Un jeton LÉGITIME issu
    d'une rotation pendant une panne du JWKS était donc annoncé comme forgé.

    ⚠️ La seconde méthode ci-dessous est la GARDE DE SÉCURITÉ de ce correctif : quand
    le refresh n'a PAS été tenté, le refus doit rester `unknown_kid`. Sinon un appelant
    présentant des `kid` forgés obtiendrait une classe re-tentable au lieu d'un refus.
    """

    @staticmethod
    def _cache(fetchs):
        """`fetchs` : liste de callables, un par appel de fetch, dans l'ordre."""
        from test_mission_jwt import _make_es256_keypair, _make_jwks

        import json

        from mcp_vault.auth.mission_jwt import JWKSCache

        _, pub = _make_es256_keypair()
        appels = [0]
        horloge = [1000.0]

        def fetch(url, etag, timeout):
            i = appels[0]
            appels[0] += 1
            action = fetchs[i] if i < len(fetchs) else fetchs[-1]
            if action == "ok":
                return 200, None, json.dumps(_make_jwks(pub, kid="real")).encode()
            raise OSError("JWKS injoignable (panne simulée)")

        return (JWKSCache("http://mock/x", ttl_seconds=300, fetch=fetch,
                          time_func=lambda: horloge[0]),
                appels, horloge)

    def test_un_refresh_TENTE_et_echoue_annonce_l_indisponibilite(self):
        from mcp_vault.auth.mission_jwt import JWKSUnavailable

        cache, appels, _ = self._cache(["ok", "panne"])
        cache.get_key("real")                      # peuple le cache
        assert appels[0] == 1, "le témoin de peuplement n'a pas fetché"

        with pytest.raises(JWKSUnavailable):
            cache.get_key("kid-issu-d-une-rotation")

        assert appels[0] == 2, (
            "le refresh forcé doit avoir été TENTÉ — sans quoi ce test ne mesure pas "
            f"le bon chemin ; {appels[0]} fetch(s)"
        )

    def test_un_refresh_NON_TENTE_reste_un_refus_ferme(self):
        """⚠️ Garde de sécurité : throttle anti-DoS ou backoff ⇒ nous avons CHOISI de
        ne pas aller voir. Le refus doit rester ferme, jamais re-tentable."""
        from mcp_vault.auth.mission_jwt import JWKSUnavailable, MissionTokenInvalid

        cache, appels, _ = self._cache(["ok", "ok"])
        cache.get_key("real")
        with pytest.raises(MissionTokenInvalid):
            cache.get_key("ghost-1")               # consomme la fenêtre de throttle
        n = appels[0]

        with pytest.raises(MissionTokenInvalid):   # et NON JWKSUnavailable
            cache.get_key("ghost-2")

        assert appels[0] == n, (
            "le throttle doit avoir empêché le second refresh, sinon ce test ne "
            f"mesure pas le cas « non tenté » ; {appels[0]} fetch(s) contre {n}"
        )
        assert JWKSUnavailable is not MissionTokenInvalid  # classes bien distinctes
