"""#148 — le rafraîchissement JWKS ne gèle plus la boucle d'événements.

`JWKSCache._refetch_locked` fait un `httpx.get` **synchrone**. Atteint depuis une
coroutine, il monopolise l'unique thread qui sert TOUTES les requêtes — même
classe de défaut que #110, autre transport. Mesuré en production le 17/08 :
117,2 ms par rafraîchissement, jusqu'à 5 s de délai d'attente.

Trois chemins y menaient, tous des coroutines :
  1. `AuthMiddleware._validate_mission_jwt` (PEP transport) ;
  2. `secret_consume` — le déballage de CHAQUE enveloppe de credentials, car
     `mcp-agent` y présente un `mission_token` ES256 à chaque appel ;
  3. `POST /admin/api/auth/jwks/reload` — le plus lent, il force le fetch.

⚠️ CE QUE CES TESTS PROUVENT, ET COMMENT. Aucun ne mesure une durée : un seuil de
temps est fragile en intégration continue et n'établit aucune causalité. Deux
formes seulement :

  - **un ORDRE** : le témoin est échantillonné DEPUIS le thread encore bloqué
    (harnais `Barriere` de `test_s3_offload_122.py`). Si la boucle n'avait pas
    progressé à cet instant, elle était gelée ;
  - **une IDENTITÉ DE THREAD** : le fetch ne doit pas s'exécuter dans le thread de
    la boucle. Le compteur ne peut pas rester à zéro dans le cas vert — sans appel
    du fetch, il n'y a pas d'identifiant à comparer, et l'assertion tombe.

⚠️ **Les jetons sont de VRAIS JWT ES256.** Première rédaction de ce banc : un jeton
factice `"a.b.c"`, rejeté au parsing d'en-tête **avant** d'atteindre le cache. Le
fetch n'avait donc jamais lieu et le témoin attendait indéfiniment. Un en-tête
lisible avec `kid` est la condition pour que le mécanisme éprouvé s'exécute.

⚠️ Ce lot ne réécrit PAS `JWKSCache` : il est déjà thread-safe (`threading.Lock`),
et son fail-close, son backoff et son throttle « kid inconnu » doivent survivre
intacts. La dernière section le vérifie.
"""

import asyncio
import json
import threading
from types import SimpleNamespace
from unittest.mock import patch

import jwt as _pyjwt
import pytest

_GARDE_SECONDES = 10.0


def _run(coro):
    return asyncio.run(coro)


# ── Clés, JWKS et jetons réels ──────────────────────────────────────────────


def _paire_es256(kid: str = "kid-1"):
    """Une vraie clé P-256 : le JWKS doit être exploitable par le validateur."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwt.algorithms import ECAlgorithm

    cle = ec.generate_private_key(ec.SECP256R1())
    publique = json.loads(ECAlgorithm.to_jwk(cle.public_key()))
    publique.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return cle, {"keys": [publique]}


def _jeton(cle, kid: str = "kid-1") -> str:
    """Un JWT ES256 dont l'en-tête est LISIBLE (alg + kid).

    Ses claims sont volontairement incomplets : la validation échouera APRÈS la
    résolution de clé. C'est exactement ce qu'on veut — le fetch a lieu, puis la
    fonction rend son refus sans aller solliciter les magasins d'autorisation.
    """
    return _pyjwt.encode({"iss": "mcp-mission"}, cle, algorithm="ES256",
                         headers={"kid": kid})


def _cache(fetch, ttl: int = 60):
    """Un cache JWKS NON peuplé : le premier accès déclenche donc un fetch."""
    from mcp_vault.auth.mission_jwt import JWKSCache

    return JWKSCache("https://mission.interne/.well-known/jwks.json", ttl,
                     fetch=fetch, timeout=1.0)


# ── Harnais : une barrière qui échantillonne le témoin depuis son thread ─────


class BarriereJWKS:
    """Faux fetch JWKS bloquant, instrumenté.

    Ne rend la main que sur libération explicite, et note AVANT de sortir si la
    boucle avait progressé — l'échantillon est pris depuis le thread bloqué.
    """

    def __init__(self, corps: bytes = None, exception: BaseException = None):
        self.entree = threading.Event()
        self.liberation = threading.Event()
        self.temoin_a_progresse = False
        self.temoin_avant_sortie = None
        self.appels = 0
        self.threads = []
        self._corps = corps
        self._exception = exception

    def __call__(self, url, etag, timeout):
        self.appels += 1
        self.threads.append(threading.get_ident())
        self.entree.set()
        self.liberation.wait(timeout=_GARDE_SECONDES)
        self.temoin_avant_sortie = self.temoin_a_progresse
        if self._exception is not None:
            raise self._exception
        return 200, "etag-1", self._corps


class FetchInstantane:
    """Faux fetch non bloquant : ne sert qu'à relever le thread d'exécution."""

    def __init__(self, corps: bytes):
        self.appels = 0
        self.threads = []
        self._corps = corps

    def __call__(self, url, etag, timeout):
        self.appels += 1
        self.threads.append(threading.get_ident())
        return 200, "etag-1", self._corps


async def _temoin(barriere: BarriereJWKS) -> None:
    """Ne peut progresser que si la boucle d'événements est vivante."""
    debut = asyncio.get_running_loop().time()
    while not barriere.entree.is_set():
        if asyncio.get_running_loop().time() - debut > _GARDE_SECONDES:
            # Garde anti-pendaison : si le fetch n'est jamais appelé, l'assertion
            # de `_assert_boucle_restee_vivante` doit tomber, pas le banc pendre.
            return
        await asyncio.sleep(0.001)
    barriere.temoin_a_progresse = True
    barriere.liberation.set()


async def _avec_temoin(barriere: BarriereJWKS, operation):
    resultats = await asyncio.gather(operation, _temoin(barriere),
                                     return_exceptions=True)
    return resultats[0]


def _assert_boucle_restee_vivante(barriere: BarriereJWKS, quoi: str):
    assert barriere.entree.is_set(), f"{quoi} : le fetch JWKS n'a JAMAIS été appelé"
    assert barriere.temoin_avant_sortie is True, (
        f"{quoi} : la boucle d'événements était GELÉE pendant le fetch JWKS "
        "(le témoin n'avait pas progressé au moment de sortir du stub)"
    )


def _coroutine_qui_rend(valeur):
    async def _f(*a, **k):
        return valeur
    return _f


class _ValidateurQuiResoutLaCle:
    """Double du validateur `secret_consume` : sa validation touche le cache JWKS.

    C'est le seul comportement qui compte ici — le reste du contrat de validation
    est éprouvé par `test_mission_jwt.py`.
    """

    def __init__(self, cache):
        self._cache = cache

    def validate(self, jeton):
        self._cache.get_key("kid-1")
        return {"mission_id": "m1", "tenant_id": "t1"}


# ── 1. Le défaut lui-même : la boucle survit à un JWKS gelé ─────────────────


class TestLaBoucleResteVivanteSousUnJWKSGele:
    def test_le_PEP_transport_offloade_la_validation(self):
        """Site 1 — `AuthMiddleware._validate_mission_jwt`."""
        from mcp_vault.auth import middleware as m

        cle, jwks = _paire_es256()
        barriere = BarriereJWKS(corps=json.dumps(jwks).encode())
        cache = _cache(barriere)

        reglages = SimpleNamespace(resolved_mission_aud="mcp-vault:test:v1",
                                   mcp_component_kind="vault",
                                   mission_token_leeway_seconds=10)
        middleware = m.AuthMiddleware.__new__(m.AuthMiddleware)

        with patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache):
            _run(_avec_temoin(
                barriere,
                middleware._validate_mission_jwt(_jeton(cle), reglages),
            ))

        _assert_boucle_restee_vivante(barriere, "PEP transport")

    def test_secret_consume_offloade_la_validation(self):
        """Site 2 — le chemin de déballage des credentials, le plus fréquent."""
        from mcp_vault import server as s

        cle, jwks = _paire_es256()
        barriere = BarriereJWKS(corps=json.dumps(jwks).encode())
        cache = _cache(barriere)

        reglages = SimpleNamespace(
            enforce_mission_token_validation=False,
            mission_jwks_url="https://mission.interne/.well-known/jwks.json",
            mission_status_url="", mission_status_cache_ttl=0,
            mission_token_aud="mcp-vault:test:v1",
            resolved_mission_aud="mcp-vault:test:v1",
        )

        with patch.object(s, "settings", reglages), \
             patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
             patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache), \
             patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
                   return_value=_ValidateurQuiResoutLaCle(cache)), \
             patch("mcp_vault.vault.wrapping.consume_wrap_secret",
                   new=_coroutine_qui_rend({"status": "ok"})):
            _run(_avec_temoin(
                barriere,
                s.secret_consume(wrap_token="t", operation_id="op-1",
                                 mission_token=_jeton(cle)),
            ))

        _assert_boucle_restee_vivante(barriere, "secret_consume")

    def test_le_rechargement_admin_offloade_le_fetch(self):
        """Site 3 — le plus lent : `force_reload` ne bénéficie jamais du cache."""
        from mcp_vault.admin import api as a

        _, jwks = _paire_es256()
        barriere = BarriereJWKS(corps=json.dumps(jwks).encode())
        cache = _cache(barriere)
        envois = []

        async def send(message):
            envois.append(message)

        with patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache):
            _run(_avec_temoin(barriere, a._api_jwks_reload(send)))

        _assert_boucle_restee_vivante(barriere, "rechargement admin")
        assert envois, "aucune réponse HTTP émise"

    def test_la_sonde_repond_pendant_qu_un_fetch_JWKS_est_bloque(self):
        """Le mécanisme de l'incident #110, rejoué sur le transport JWKS.

        Ce n'est pas « la sonde appelle-t-elle le JWKS ? » — elle ne l'a jamais
        fait. C'est « une AUTRE requête gèle-t-elle la boucle au point que la
        sonde fasse la queue derrière ? ». La réponse de la sonde est échantillonnée
        depuis le thread encore bloqué : c'est un ORDRE, pas une durée.
        """
        from mcp_vault.admin import api as a

        _, jwks = _paire_es256()
        barriere = BarriereJWKS(corps=json.dumps(jwks).encode())
        cache = _cache(barriere)
        sonde = {"repondu": False, "statut": None}

        async def interroger_la_sonde():
            debut = asyncio.get_running_loop().time()
            while not barriere.entree.is_set():
                if asyncio.get_running_loop().time() - debut > _GARDE_SECONDES:
                    return
                await asyncio.sleep(0.001)
            from mcp_vault.lifecycle import availability_status
            sonde["statut"], _ = await availability_status()
            sonde["repondu"] = True
            barriere.temoin_a_progresse = True
            barriere.liberation.set()

        async def scenario():
            async def send(message):
                pass
            await asyncio.gather(a._api_jwks_reload(send), interroger_la_sonde(),
                                 return_exceptions=True)

        with patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache), \
             patch("mcp_vault.openbao.manager.probe_openbao",
                   new=_coroutine_qui_rend(
                       SimpleNamespace(ok=True, sealed=False, detail="unsealed"))), \
             patch("mcp_vault.lifecycle.startup_is_ready", return_value=True):
            _run(scenario())

        assert barriere.entree.is_set(), "le fetch JWKS n'a jamais démarré"
        assert sonde["repondu"] is True, "la sonde n'a pas répondu du tout"
        assert barriere.temoin_avant_sortie is True, (
            "la sonde n'avait PAS répondu au moment où le fetch JWKS sortait — "
            "la boucle était gelée derrière lui"
        )


# ── 2. L'identité de thread : le fetch quitte VRAIMENT la boucle ────────────


class TestLeFetchNeTourneJamaisDansLeThreadDeLaBoucle:
    """Formulation directe de la propriété, par site.

    Un test de vivacité peut passer si le stub est rapide ; celui-ci ne peut pas :
    il compare l'identifiant de thread du fetch à celui de la boucle. Et il ne
    peut pas être vert sans que le fetch ait tourné — sans appel, aucun
    identifiant à comparer, et l'assertion sur `appels` tombe.
    """

    def test_le_rechargement_admin_fetch_hors_du_thread_de_la_boucle(self):
        from mcp_vault.admin import api as a

        _, jwks = _paire_es256()
        fetch = FetchInstantane(json.dumps(jwks).encode())
        cache = _cache(fetch)
        idents = {}

        async def scenario():
            idents["boucle"] = threading.get_ident()

            async def send(message):
                pass
            await a._api_jwks_reload(send)

        with patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache):
            _run(scenario())

        assert fetch.appels == 1, "le fetch n'a pas eu lieu — le test ne prouve rien"
        assert fetch.threads[0] != idents["boucle"], (
            "le fetch JWKS s'est exécuté DANS le thread de la boucle d'événements"
        )

    def test_le_PEP_transport_fetch_hors_du_thread_de_la_boucle(self):
        from mcp_vault.auth import middleware as m

        cle, jwks = _paire_es256()
        fetch = FetchInstantane(json.dumps(jwks).encode())
        cache = _cache(fetch)
        idents = {}

        reglages = SimpleNamespace(resolved_mission_aud="mcp-vault:test:v1",
                                   mcp_component_kind="vault",
                                   mission_token_leeway_seconds=10)
        middleware = m.AuthMiddleware.__new__(m.AuthMiddleware)

        async def scenario():
            idents["boucle"] = threading.get_ident()
            await middleware._validate_mission_jwt(_jeton(cle), reglages)

        with patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache):
            _run(scenario())

        assert fetch.appels >= 1, "le fetch n'a pas eu lieu — le test ne prouve rien"
        assert all(t != idents["boucle"] for t in fetch.threads), (
            "le fetch JWKS s'est exécuté DANS le thread de la boucle d'événements"
        )

    def test_secret_consume_fetch_hors_du_thread_de_la_boucle(self):
        from mcp_vault import server as s

        cle, jwks = _paire_es256()
        fetch = FetchInstantane(json.dumps(jwks).encode())
        cache = _cache(fetch)
        idents = {}

        reglages = SimpleNamespace(
            enforce_mission_token_validation=False,
            mission_jwks_url="https://mission.interne/.well-known/jwks.json",
            mission_status_url="", mission_status_cache_ttl=0,
            mission_token_aud="mcp-vault:test:v1",
            resolved_mission_aud="mcp-vault:test:v1",
        )

        async def scenario():
            idents["boucle"] = threading.get_ident()
            return await s.secret_consume(wrap_token="t", operation_id="op-1",
                                          mission_token=_jeton(cle))

        with patch.object(s, "settings", reglages), \
             patch("mcp_vault.auth.context.enforce_wrap_only_token", return_value=None), \
             patch("mcp_vault.auth.mission_jwt.get_jwks_cache", return_value=cache), \
             patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
                   return_value=_ValidateurQuiResoutLaCle(cache)), \
             patch("mcp_vault.vault.wrapping.consume_wrap_secret",
                   new=_coroutine_qui_rend({"status": "ok"})):
            _run(scenario())

        assert fetch.appels == 1, "le fetch n'a pas eu lieu — le test ne prouve rien"
        assert fetch.threads[0] != idents["boucle"], (
            "le fetch JWKS s'est exécuté DANS le thread de la boucle d'événements"
        )


# ── 3. Ce que le lot ne doit PAS avoir changé ──────────────────────────────


class TestLesGarantiesDuCacheSurviventIntactes:
    """Le déport hors boucle ne doit toucher NI le fail-close, NI le backoff, NI
    le throttle « kid inconnu » — trois protections distinctes. Les déplacer sans
    les comprendre rouvrirait un martèlement de l'endpoint de `mcp-mission`
    (avertissement porté à la fiche #148)."""

    def test_un_cache_PERIME_n_est_jamais_servi(self):
        """Fail-close : la garantie centrale du module."""
        import httpx

        from mcp_vault.auth.mission_jwt import JWKSUnavailable

        _, jwks = _paire_es256()
        corps = json.dumps(jwks).encode()
        etat = {"tour": 0}

        def fetch(url, etag, timeout):
            etat["tour"] += 1
            if etat["tour"] == 1:
                return 200, "e1", corps
            raise httpx.ConnectError("endpoint injoignable")

        cache = _cache(fetch, ttl=60)
        assert cache.get_key("kid-1")["kid"] == "kid-1"  # peuplé

        cache._fetched_at -= 61  # périmé, sans attendre
        with pytest.raises(JWKSUnavailable):
            cache.get_key("kid-1")  # périmé + fetch en échec ⇒ REFUS

    def test_le_throttle_kid_inconnu_borne_toujours_les_fetch(self):
        """Anti-DoS : un flot de `kid` inconnus ne doit pas faire un fetch par
        requête. Sans ce throttle, le déport hors boucle transformerait un gel en
        martèlement — notre service tiendrait, leur endpoint non."""
        from mcp_vault.auth.mission_jwt import MissionTokenInvalid

        _, jwks = _paire_es256()
        fetch = FetchInstantane(json.dumps(jwks).encode())
        cache = _cache(fetch, ttl=3600)  # frais : seul le kid inconnu peut déclencher

        cache.get_key("kid-1")
        base = fetch.appels

        for _ in range(20):
            with pytest.raises(MissionTokenInvalid):
                cache.get_key("kid-jamais-publie")

        supplementaires = fetch.appels - base
        assert supplementaires <= 1, (
            f"{supplementaires} fetch pour 20 kid inconnus — le throttle est tombé"
        )

    def test_le_backoff_est_toujours_programme_sur_echec(self):
        import httpx

        from mcp_vault.auth.mission_jwt import JWKSUnavailable

        def fetch(url, etag, timeout):
            raise httpx.ConnectError("boom")

        cache = _cache(fetch, ttl=60)
        with pytest.raises(JWKSUnavailable):
            cache.get_key("kid-1")

        assert cache._fail_count == 1
        assert cache._next_attempt_at > 0.0, "aucun backoff programmé"

    def test_un_seul_thread_d_executeur_est_engage_sur_un_rafraichissement(self):
        """⚠️ RÉGRESSION relevée en revue adversariale — et première rédaction de ce
        test JETÉE parce qu'elle ne prouvait rien.

        Le défaut : chaque validation prend un thread de l'exécuteur **partagé avec
        les offloads S3** (#122/#123), PUIS attend le verrou du cache. Sur un
        endpoint JWKS lent ou tombé, N requêtes mission y attendent en thread et
        les lectures S3 font la queue derrière — on répare #110 sur un transport en
        le recréant sur l'autre.

        La première version de ce test affirmait cette propriété avec un fetch
        INSTANTANÉ : elle ne mesurait ni les threads bloqués, ni l'exécuteur. Elle
        aurait passé avec ou sans la borne.

        Ici, le fetch BLOQUE et on mesure l'occupation MAXIMALE de l'exécuteur :
        combien d'appels déportés sont simultanément en vol. La borne est 1.
        """
        import functools

        from mcp_vault.auth.mission_jwt import valider_hors_boucle

        _, jwks = _paire_es256()
        corps = json.dumps(jwks).encode()

        occupation = {"courante": 0, "maximale": 0}
        mesure = threading.Lock()
        premier_entre = threading.Event()
        liberation = threading.Event()
        libere = {"par_le_scenario": False, "avant_sortie": None}

        def fetch(url, etag, timeout):
            # Le PREMIER thread à entrer dort jusqu'à libération : c'est la fenêtre
            # pendant laquelle les autres candidats doivent NE PAS occuper de thread.
            if not premier_entre.is_set():
                premier_entre.set()
                liberation.wait(timeout=_GARDE_SECONDES)
                # ÉCHANTILLON pris DEPUIS LE THREAD, à l'instant de sortir. C'est
                # le seul témoin qui vaille : un drapeau relu après coup dirait
                # seulement que le scénario a FINI par tourner, pas qu'il a tourné
                # à temps — une boucle gelée 10 s puis débloquée par le délai de
                # garde le poserait quand même.
                libere["avant_sortie"] = libere["par_le_scenario"]
            return 200, "etag-1", corps

        cache = _cache(fetch, ttl=3600)  # non peuplé ⇒ le 1er accès rafraîchit

        def resolution_instrumentee():
            with mesure:
                occupation["courante"] += 1
                occupation["maximale"] = max(occupation["maximale"],
                                             occupation["courante"])
            try:
                return cache.get_key("kid-1")
            finally:
                with mesure:
                    occupation["courante"] -= 1

        async def liberer_quand_tous_engages():
            # Laisse aux 8 coroutines le temps de se présenter, puis libère.
            debut = asyncio.get_running_loop().time()
            while not premier_entre.is_set():
                if asyncio.get_running_loop().time() - debut > _GARDE_SECONDES:
                    break
                await asyncio.sleep(0.001)
            await asyncio.sleep(0.15)
            libere["par_le_scenario"] = True
            liberation.set()

        async def scenario():
            candidats = [
                valider_hors_boucle(cache, functools.partial(resolution_instrumentee))
                for _ in range(8)
            ]
            resultats, _ = await asyncio.gather(
                asyncio.gather(*candidats, return_exceptions=True),
                liberer_quand_tous_engages(),
            )
            return resultats

        resultats = _run(scenario())

        assert premier_entre.is_set(), "aucun rafraîchissement n'a démarré"

        # ⚠️ LE DISCRIMINANT, et il aurait attrapé la version précédente de ce test.
        # Elle était verte alors que la boucle était BLOQUÉE : son libérateur ne
        # tournait jamais, et c'est le délai de garde du faux fetch qui le libérait
        # tout seul — le compteur observait alors 1 par accident. Ce n'est pas une
        # durée qu'on éprouve ici, c'est un ORDRE : le scénario doit avoir pu
        # s'exécuter et libérer, ce qui exige une boucle vivante.
        assert libere["avant_sortie"] is True, (
            "la boucle était BLOQUÉE : au moment où le fetch sortait, le scénario "
            "n'avait pas encore libéré — c'est donc le délai de garde du faux fetch "
            "qui l'a débloqué, et la mesure d'occupation ne vaut rien"
        )
        assert all(isinstance(r, dict) and r["kid"] == "kid-1" for r in resultats), (
            f"toutes les résolutions doivent aboutir : {resultats}"
        )
        assert occupation["maximale"] == 1, (
            f"{occupation['maximale']} appels déportés simultanés — l'exécuteur "
            "partagé avec les offloads S3 est affamé pendant un fetch JWKS lent"
        )
