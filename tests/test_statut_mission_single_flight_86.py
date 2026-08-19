"""#86 finding 5 — stampede et cache non borné sur le statut de mission.

`check_mission_active` prenait un verrou asyncio pour LIRE le cache, le RELÂCHAIT, puis
faisait l'appel HTTP sortant hors verrou. N appels concurrents sur la MÊME mission
produisaient donc N appels sortants.

⚠️ POURQUOI CE DÉFAUT COMPTE, ET CE N'EST PAS LA MÉMOIRE. L'endpoint de statut de
`mcp-mission` est **mono-instance et partagé avec l'exécution des missions**. Un éventail
de 11 ouvriers appelant `secret_consume` ensemble produisait 11 appels sortants pour la
même mission : nous amplifiions la charge sur un service fragile au moment précis où il
est en peine. Même forme que #148 (nous gelions la boucle) et #152 (nous annoncions sa
panne comme une faute de l'appelant).

⚠️⚠️ LA GARDE CONTRE LE MAUVAIS CORRECTIF — lire avant de « simplifier ».
Le correctif évident est de TENIR le verrou global pendant l'appel HTTP. **Mesuré : ce
serait pire.** Onze missions DIFFÉRENTES se résolvent en 0,30 s ; derrière un verrou
global elles se sérialiseraient à ~3,3 s, et un endpoint lent bloquerait TOUTES les
missions au lieu d'une. La sérialisation porte donc sur `mission_id`, et le registre des
appels en vol se vide de lui-même — sinon il deviendrait la fuite mémoire que ce lot
corrige.
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from mcp_vault.auth import mission_jwt as mj

URL = "http://mission.interne/api/v1/missions/{mission_id}/status"
TTL = 30


class _Reponse:
    status_code = 200

    def json(self):
        return {"status": "RUNNING"}


def _client_espion(appels: list, latence: float):
    """Faux `httpx.AsyncClient` qui COMPTE les appels sortants."""

    class _C:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            appels.append(url)
            await asyncio.sleep(latence)
            return _Reponse()

    return _C


async def _lancer(n: int, latence: float, meme_mission: bool):
    mj._mission_status_cache.clear()
    mj._mission_status_en_vol.clear()
    appels = []
    with patch.object(mj.httpx, "AsyncClient", _client_espion(appels, latence)):
        t0 = time.perf_counter()
        verdicts = await asyncio.gather(*[
            mj.check_mission_active(
                "mis_identique" if meme_mission else f"mis_{i}", URL, TTL,
            )
            for i in range(n)
        ])
        duree = time.perf_counter() - t0
    return len(appels), duree, verdicts


class TestLeBancCompteVraimentLesAppels:
    """⚠️ GARDE ANTI-TEST-CREUX. Sans ce témoin, « un seul appel sortant » pourrait
    signifier « le harnais n'appelle rien » ou « tout sort du cache »."""

    def test_un_appel_isole_produit_UN_appel_sortant(self):
        appels, _, verdicts = asyncio.run(_lancer(1, 0.0, meme_mission=True))

        assert appels == 1, f"le banc ne compte pas les appels sortants ({appels})"
        assert verdicts[0][0] is True, f"mission attendue active : {verdicts[0]!r}"


class TestUnEventailNeDoitPasMultiplierLesAppelsSortants:
    def test_onze_ouvriers_sur_la_MEME_mission_font_UN_seul_appel(self):
        appels, _, verdicts = asyncio.run(_lancer(11, 0.30, meme_mission=True))

        assert appels == 1, (
            "un éventail de 11 ouvriers sur la même mission doit produire UN appel "
            f"sortant, pas {appels} — sinon nous amplifions la charge sur l'endpoint "
            "mono-instance de mcp-mission"
        )
        assert all(ok for ok, _ in verdicts), (
            f"les 11 appelants doivent tous recevoir le verdict : {verdicts!r}"
        )

    def test_le_verdict_est_bien_PARTAGE_et_non_deduit(self):
        """Les suiveurs doivent recevoir le résultat de l'appel RÉEL, pas un défaut
        optimiste : vérifié sur une mission INACTIVE."""
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()
        appels = []

        class _Inactive:
            status_code = 200

            def json(self):
                return {"status": "ABORTED"}

        class _C:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url):
                appels.append(url)
                await asyncio.sleep(0.20)
                return _Inactive()

        async def _huit():
            return await asyncio.gather(*[
                mj.check_mission_active("mis_abortee", URL, TTL) for _ in range(8)
            ])

        with patch.object(mj.httpx, "AsyncClient", _C):
            verdicts = asyncio.run(_huit())

        assert len(appels) == 1, f"{len(appels)} appels sortants au lieu d'un"
        assert not any(ok for ok, _ in verdicts), (
            "une mission abortée doit être refusée à TOUS les appelants, y compris aux "
            f"suiveurs du single-flight : {verdicts!r}"
        )


class TestLaSerialisationNeDoitPasEtreGLOBALE:
    """⚠️ Garde contre le correctif naïf (verrou global tenu pendant l'appel HTTP)."""

    def test_onze_missions_DIFFERENTES_ne_se_serialisent_pas(self):
        appels, duree, _ = asyncio.run(_lancer(11, 0.30, meme_mission=False))

        assert appels == 11, (
            f"11 missions distinctes exigent 11 appels — {appels} signifierait que le "
            "single-flight confond des missions différentes, ce qui serait une faille "
            "de cloisonnement bien pire que le stampede"
        )
        assert duree < 1.2, (
            f"les 11 appels ont pris {duree:.2f}s : ils sont sérialisés. La borne est "
            "large (0,30s attendu) mais un verrou GLOBAL donnerait ~3,3s"
        )


class TestLeRegistreDesAppelsEnVolSeVide:
    """Un dictionnaire d'appels en vol qui ne se vide pas serait la fuite que ce lot
    corrige, déplacée d'un cran."""

    def test_aucune_entree_ne_survit_a_la_resolution(self):
        asyncio.run(_lancer(11, 0.05, meme_mission=True))

        assert mj._mission_status_en_vol == {}, (
            f"registre non vidé après résolution : {list(mj._mission_status_en_vol)!r}"
        )

    def test_aucune_entree_ne_survit_a_une_PANNE(self):
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()

        class _CPanne:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url):
                raise OSError("endpoint injoignable")

        async def _cinq():
            return await asyncio.gather(*[
                mj.check_mission_active("mis_panne", URL, TTL) for _ in range(5)
            ])

        with patch.object(mj.httpx, "AsyncClient", _CPanne):
            verdicts = asyncio.run(_cinq())

        assert not any(ok for ok, _ in verdicts), "fail-close attendu sur panne"
        assert mj._mission_status_en_vol == {}, (
            "une panne doit vider le registre comme un succès — sinon la mission "
            "reste bloquée sur une future orpheline"
        )


class TestLeCacheEstBorne:
    def test_le_cache_ne_croit_pas_indefiniment(self):
        """Avant correctif : 5 000 missions distinctes laissaient 5 000 entrées."""
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()
        appels = []

        async def _beaucoup():
            for i in range(3000):
                await mj.check_mission_active(f"mis_{i}", URL, TTL)

        with patch.object(mj.httpx, "AsyncClient", _client_espion(appels, 0.0)):
            asyncio.run(_beaucoup())

        assert len(appels) == 3000, (
            f"témoin : 3000 appels sortants attendus, {len(appels)} observés"
        )
        # ⚠️ Borne EN DUR, jamais `mj._MISSION_STATUS_CACHE_MAX` : une assertion qui
        # se compare à la constante qu'elle est censée protéger ne peut pas échouer
        # quand on relève la constante. Le banc de mutations l'a démontré — cette
        # assertion a d'abord SURVÉCU à un passage de 1024 à 10 000 000.
        assert len(mj._mission_status_cache) <= 2048, (
            f"{len(mj._mission_status_cache)} entrées en cache après 3000 missions "
            "distinctes : le dictionnaire n'est pas borné"
        )
        assert len(mj._mission_status_cache) < 3000, (
            "le cache croît avec le nombre de missions vues — c'est la fuite que ce "
            "lot corrige"
        )


# ── #86 finding 4 (revue de plan) — la taxonomie jusqu'à secret_consume ──────

MISSION_REELLE = "mis_cbd8f9e745ebf1899ab565db"
OP = "op-86"


def _consommer_avec_statut(statut_http=None, etat=None, enforce=True):
    """Exécute `secret_consume` de bout en bout avec un service de statut simulé.

    `statut_http` : code non-200 à rendre. `etat` : état rendu par un 200.
    Rend (résultat, état de l'entrée de registre).
    """
    import sys as _sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from mcp_vault import server as s
    from mcp_vault.store_refresh import Freshness
    from mcp_vault.vault.wrapping import WrapRegistry

    mj._mission_status_cache.clear()
    mj._mission_status_en_vol.clear()

    class _Reg(WrapRegistry):
        def __init__(self):
            self._wraps = [{
                "operation_id": OP, "accessor": "ACC", "mission_id": MISSION_REELLE,
                "vault_id": "v", "secret_path": "p",
                "created_at": "2026-08-19T09:00:00+00:00", "expires_at": "",
                # Binding C18 COMPLET : en mode durci, `tenant_id` et
                # `expected_aud` sont exigés non blancs (#78). Le banc exerce donc le
                # chemin réellement durci, pas une variante permissive.
                "status": "active", "tenant_id": "t-canari",
                "expected_aud": "mcp-vault:test:v1",
            }]
            self.freshness = Freshness()
            self.freshness.mark_success()
            self._last_load_ok = True
            self.refresh_lock = asyncio.Lock()

        def load(self):
            pass

        def _save(self):
            return True

    class _Statut:
        status_code = statut_http or 200

        def json(self):
            return {"status": etat or "RUNNING"}

    class _CStatut:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            if statut_http is None and etat is None:
                raise OSError("service de missions injoignable")
            return _Statut()

    class _ValidateurOK:
        def validate(self, jeton):
            return {"mission_id": MISSION_REELLE, "tenant_id": "t-canari"}

    reglages = SimpleNamespace(
        enforce_mission_token_validation=enforce,
        mission_jwks_url="https://mission.interne/jwks",
        mission_status_url=URL, mission_status_cache_ttl=30,
        mission_token_aud="mcp-vault:test:v1",
        resolved_mission_aud="mcp-vault:test:v1",
        mcp_component_kind="vault", mission_token_leeway_seconds=10,
    )
    reg = _Reg()
    mock_hvac = MagicMock()
    eph = MagicMock()
    mock_hvac.Client.return_value = eph
    eph.sys.unwrap.return_value = {"data": {"data": {"k": "v"}, "metadata": {}}}
    cfg = MagicMock()
    cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch.dict(_sys.modules, {"hvac": mock_hvac}), \
         patch.object(s, "settings", reglages), \
         patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
         patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=None), \
         patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
               return_value=_ValidateurOK()), \
         patch.object(mj.httpx, "AsyncClient", _CStatut), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=MagicMock()), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        res = asyncio.run(s.secret_consume(wrap_token="wt", operation_id=OP,
                                          mission_token="a.b.c"))
    return res, reg._wraps[0]["status"]


class TestLeBancDeConsommationSaitAboutir:
    """⚠️ GARDE ANTI-TEST-CREUX : sans ce témoin, un refus ne prouverait qu'un harnais
    cassé."""

    def test_une_mission_ACTIVE_consomme_reellement(self):
        res, statut = _consommer_avec_statut(etat="RUNNING")

        assert res["status"] == "ok", f"le banc ne sait pas aboutir : {res!r}"
        assert statut == "consumed", f"entrée restée à {statut!r}"


class TestUnePanneDuServiceDeMissionsNEstPasUneMissionRevoquee:
    """#86 finding 4 (revue de plan). `secret_consume` fondait TOUT verdict négatif en
    `mission_inactive`. Or `mcp-agent` lit tout code ≠ `backend_unavailable` en
    consommation incertaine (#135) ⇒ secret condamné et, depuis #49, arrêt terminal de
    mission AVEC alerte de sécurité. Une panne de leur service de statut mono-instance
    se lisait donc comme une révocation. Troisième occurrence du défaut de #152/#154.
    """

    def test_service_injoignable_rend_backend_unavailable(self):
        res, statut = _consommer_avec_statut()  # exception réseau

        assert res["status"] == "error"
        assert res["error_type"] == "backend_unavailable", (
            "une panne du service de missions doit s'annoncer indisponible et "
            f"re-tentable, pas « mission non active » ; obtenu {res!r}"
        )
        assert statut == "active", (
            f"aucun déballage ne doit avoir été tenté ; entrée passée à {statut!r}"
        )

    @pytest.mark.parametrize("code", [404, 429, 500, 503])
    def test_tout_non_200_rend_aussi_backend_unavailable(self, code):
        res, statut = _consommer_avec_statut(statut_http=code)

        assert res["error_type"] == "backend_unavailable", (
            f"HTTP {code} du service de missions : obtenu {res!r}"
        )
        assert statut == "active"

    def test_une_mission_REELLEMENT_abortee_reste_mission_inactive(self):
        """⚠️ Contre-épreuve : l'étroitesse compte. Un état rendu par un 200 EST un fait
        sur la mission — le confondre avec une panne rendrait le nouveau code un
        fourre-tout et ferait re-tenter un refus définitif."""
        res, statut = _consommer_avec_statut(etat="ABORTED")

        assert res["error_type"] == "mission_inactive", (
            f"une mission abortée doit rester un refus ferme ; obtenu {res!r}"
        )
        assert statut == "active", "aucun déballage sur mission abortée"


class TestLIndisponibiliteEstMiseEnCacheBRIEVEMENT:
    def test_deux_appels_rapproches_sur_une_panne_ne_font_QU_UN_appel(self):
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()
        appels = []

        class _CPanne:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url):
                appels.append(url)
                raise OSError("injoignable")

        async def _deux_sequentiels():
            a = await mj.check_mission_active("mis_p", URL, TTL)
            b = await mj.check_mission_active("mis_p", URL, TTL)
            return a, b

        with patch.object(mj.httpx, "AsyncClient", _CPanne):
            a, b = asyncio.run(_deux_sequentiels())

        assert len(appels) == 1, (
            f"{len(appels)} appels sortants : l'indisponibilité n'est pas mise en cache"
        )
        assert a == b == (False, "service_unavailable"), (
            f"le motif servi depuis le cache doit rester une indisponibilité : {a!r} {b!r}"
        )

    def test_le_motif_cache_n_est_JAMAIS_transforme_en_fait_sur_la_mission(self):
        """⚠️ Le cache stocke le MOTIF. Avant #86, il ne stockait qu'un booléen et le
        service rendait « mission_inactive_cached » — une panne annoncée comme un fait
        sur la mission."""
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()

        class _CPanne:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url):
                raise OSError("injoignable")

        async def _puis_relire():
            await mj.check_mission_active("mis_q", URL, TTL)
            return await mj.check_mission_active("mis_q", URL, TTL)

        with patch.object(mj.httpx, "AsyncClient", _CPanne):
            _, motif = asyncio.run(_puis_relire())

        assert "inactive" not in motif, (
            f"motif servi depuis le cache : {motif!r} — impute la panne à la mission"
        )

    def test_cache_ttl_zero_signifie_vraiment_pas_de_cache(self):
        mj._mission_status_cache.clear()
        mj._mission_status_en_vol.clear()
        appels = []

        async def _trois():
            for _ in range(3):
                await mj.check_mission_active("mis_sanscache", URL, 0)

        with patch.object(mj.httpx, "AsyncClient", _client_espion(appels, 0.0)):
            asyncio.run(_trois())

        assert len(appels) == 3, (
            f"cache_ttl=0 doit interdire tout cache — {len(appels)} appels au lieu de 3"
        )
        assert mj._mission_status_cache == {}, "aucune entrée ne doit être posée"


# ── #86 finding 4 — le TTL JWKS borné, et le réglage sans effet rendu honnête ──


def _reglages_mission(**surcharges):
    from mcp_vault.config import Settings
    base = dict(
        mcp_auth_mode="jwt", mission_jwks_url="http://m/jwks",
        mcp_instance_id="vault-test", enforce_mission_token_validation=True,
        mission_status_url="http://m/status/{mission_id}",
    )
    base.update(surcharges)
    return Settings(**base)


class TestLeTTLDuCacheJWKSEstBorne:
    """#86 finding 4. Le TTL n'avait aucune borne. Or il n'est pas un réglage de
    confort : c'est la **fenêtre de propagation d'une révocation** de clé de signature
    — une clé révoquée DISPARAÎT du JWKS de `mcp-mission`. Trop grand, une clé révoquée
    reste acceptée ; nul ou négatif, chaque validation peut déclencher un fetch et fait
    de nous un amplificateur de charge sur un endpoint mono-instance.
    """

    @pytest.mark.parametrize("ttl", [0, -1, 5, 9, 61, 300, 3600])
    def test_hors_bornes_refuse_le_demarrage(self, ttl):
        ok, msg = _reglages_mission(mission_jwks_cache_ttl=ttl).check_mission_pep_config()

        assert ok is False, f"TTL {ttl}s accepté alors qu'il est hors [10,60]"
        assert "MISSION_JWKS_CACHE_TTL" in msg

    @pytest.mark.parametrize("ttl", [10, 30, 60])
    def test_dans_les_bornes_accepte(self, ttl):
        ok, msg = _reglages_mission(mission_jwks_cache_ttl=ttl).check_mission_pep_config()

        assert ok is True, f"TTL {ttl}s refusé à tort : {msg}"

    def test_la_valeur_EN_PRODUCTION_reste_acceptee(self):
        """⚠️ Garde de non-régression opérationnelle : `vault-01` tourne avec 60 s.
        Une borne qui exclurait cette valeur ferait échouer le démarrage en production."""
        ok, msg = _reglages_mission(mission_jwks_cache_ttl=60).check_mission_pep_config()

        assert ok is True, f"la valeur de production (60s) serait refusée : {msg}"

    def test_la_borne_ne_s_applique_PAS_en_standalone(self):
        """Un déploiement sans `mcp-mission` ne doit pas être contraint par une borne
        qui ne protège que la validation mission."""
        from mcp_vault.config import Settings

        ok, msg = Settings(mission_jwks_cache_ttl=3600).check_mission_pep_config()

        assert ok is True, (
            f"la borne du TTL JWKS ne doit contraindre que la validation mission : {msg}"
        )


class TestUnReglageSansEffetLeDitALExploitant:
    """#86 finding 4. `MISSION_JWKS_MAX_REFRESH_PER_MIN` était documenté comme un
    « rate-limit refresh JWKS (anti-DoS) » et n'a JAMAIS été appliqué.

    ⚠️ Il n'est PAS supprimé, et c'est délibéré : le modèle de configuration refuse les
    variables inconnues, donc retirer le champ ferait échouer le démarrage de tout
    déploiement qui le pose encore — et nous ne pouvons pas lire la configuration de
    production. Divergence assumée avec la revue de plan, qui demandait sa suppression.
    """

    def test_le_champ_existe_toujours_pour_ne_pas_casser_un_demarrage(self):
        from mcp_vault.config import Settings

        assert "mission_jwks_max_refresh_per_min" in Settings.model_fields, (
            "champ retiré : tout déploiement qui pose encore la variable échouera au "
            "démarrage (le modèle refuse les variables inconnues)"
        )

    @pytest.mark.parametrize("valeur", [1, 2, 4, 99, 0])
    def test_une_valeur_posee_par_l_exploitant_est_signalee(self, valeur):
        inertes = _reglages_mission(
            mission_jwks_max_refresh_per_min=valeur
        ).reglages_sans_effet()

        assert "MISSION_JWKS_MAX_REFRESH_PER_MIN" in inertes, (
            f"valeur {valeur} posée par l'exploitant, non signalée comme inerte"
        )

    def test_la_valeur_par_defaut_ne_bruite_PAS(self):
        """⚠️ Un signalement systématique serait du bruit : il ne doit sortir que si
        l'exploitant a POSÉ la variable."""
        assert _reglages_mission().reglages_sans_effet() == [], (
            "signalement émis à la valeur par défaut"
        )

    def test_le_demarrage_consulte_bien_cette_methode(self):
        """⚠️ Behavioural, pas textuel : on remplace la méthode par un espion et on
        vérifie que le démarrage l'appelle. Sans cela, la méthode pourrait être juste et
        n'être branchée nulle part — le défaut de « un correctif se lit avec sa garde ».
        """
        from unittest.mock import patch

        from mcp_vault import lifecycle

        appels = []
        reglages = _reglages_mission(mission_jwks_max_refresh_per_min=99)

        def _espion(_self):
            appels.append(1)
            return ["MISSION_JWKS_MAX_REFRESH_PER_MIN"]

        # Pydantic interdit d'attacher une méthode à une INSTANCE : on espionne la
        # classe, ce qui exerce le même point d'appel.
        with patch.object(type(reglages), "reglages_sans_effet", _espion), \
             patch.object(lifecycle, "get_settings", return_value=reglages):
            try:
                asyncio.run(lifecycle.vault_startup())
            except Exception:
                pass

        assert appels, (
            "le démarrage n'a pas consulté `reglages_sans_effet()` — le signalement "
            "n'atteindra jamais l'exploitant"
        )


class TestUnAppelantAnnuleNeCassePasLesAutres:
    """⚠️ `shield` est porteur : sans lui, l'annulation d'UN appelant annulerait la tâche
    PARTAGÉE et ferait échouer tous les autres.

    Le cas n'est pas théorique : `mcp-agent` borne ses appels d'outils par « le budget
    restant de l'agent », qui peut valoir quelques millisecondes (leur note du 19/08).
    Un ouvrier coupé en fin d'étape ne doit pas emporter les dix autres.
    """

    def test_l_annulation_d_un_suiveur_laisse_les_autres_aboutir(self):
        appels = []

        async def _scenario():
            mj._mission_status_cache.clear()
            mj._mission_status_en_vol.clear()
            with patch.object(mj.httpx, "AsyncClient", _client_espion(appels, 0.30)):
                taches = [
                    asyncio.create_task(mj.check_mission_active("mis_annul", URL, TTL))
                    for _ in range(6)
                ]
                await asyncio.sleep(0.05)   # tous engagés, l'appel est en vol
                taches[0].cancel()          # un seul appelant abandonne
                return await asyncio.gather(*taches[1:], return_exceptions=True)

        restants = asyncio.run(_scenario())

        assert len(appels) == 1, f"{len(appels)} appels sortants au lieu d'un"
        assert all(not isinstance(r, BaseException) for r in restants), (
            f"l'annulation d'un appelant a cassé les autres : {restants!r}"
        )
        assert all(ok for ok, _ in restants), (
            f"les survivants doivent recevoir le verdict réel : {restants!r}"
        )

    def test_l_annulation_du_MENEUR_laisse_les_suiveurs_aboutir(self):
        """Le cas que la revue de plan a fait corriger : avec une future portée par le
        meneur, son annulation faisait échouer tous les suiveurs. Avec une tâche
        détachée, l'appel poursuit."""
        appels = []

        async def _scenario():
            mj._mission_status_cache.clear()
            mj._mission_status_en_vol.clear()
            with patch.object(mj.httpx, "AsyncClient", _client_espion(appels, 0.30)):
                meneur = asyncio.create_task(
                    mj.check_mission_active("mis_meneur", URL, TTL)
                )
                await asyncio.sleep(0.05)   # le meneur a créé la tâche partagée
                suiveurs = [
                    asyncio.create_task(mj.check_mission_active("mis_meneur", URL, TTL))
                    for _ in range(4)
                ]
                await asyncio.sleep(0.02)
                meneur.cancel()
                return await asyncio.gather(*suiveurs, return_exceptions=True)

        restants = asyncio.run(_scenario())

        assert len(appels) == 1, f"{len(appels)} appels sortants au lieu d'un"
        assert all(not isinstance(r, BaseException) for r in restants), (
            f"l'annulation du meneur a cassé les suiveurs : {restants!r}"
        )
        assert all(ok for ok, _ in restants), (
            f"les suiveurs doivent recevoir le vrai verdict : {restants!r}"
        )
