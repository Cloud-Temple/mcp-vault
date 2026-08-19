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
        assert len(mj._mission_status_cache) <= mj._MISSION_STATUS_CACHE_MAX, (
            f"{len(mj._mission_status_cache)} entrées en cache pour une borne de "
            f"{mj._MISSION_STATUS_CACHE_MAX}"
        )
