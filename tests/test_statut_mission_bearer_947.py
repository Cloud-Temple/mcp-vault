"""#947 : le callback de statut présente le mission_token et lit le contrat `{mission_id, active}`.

`check_mission_active` tourne pour de vrai, avec un vrai `httpx.AsyncClient` posé sur un
`MockTransport` : en-têtes, redirections et corps sont ceux de la bibliothèque, pas d'un faux client.
Le jeton est un marqueur reconnaissable, pour prouver qu'il ne sort ni d'une URL ni d'un journal.
"""

import asyncio
import logging
import time
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from mcp_vault.auth import mission_jwt as mj

MID = "mis_0000b001"
TOKEN = "eyJ-marqueur-de-jeton-947.payload.signature"
HTTPS = "https://mission.interne/internal/missions/{mission_id}/active"
HTTP = "http://mission.interne/internal/missions/{mission_id}/active"
_REAL_CLIENT = httpx.AsyncClient


@pytest.fixture(autouse=True)
def _caches():
    mj._mission_status_cache.clear()
    mj._mission_status_en_vol.clear()
    yield
    mj._mission_status_cache.clear()
    mj._mission_status_en_vol.clear()


def _run(coro):
    return asyncio.run(coro)


def _call(handler, *, url=HTTPS, bearer=TOKEN, ttl=0, mission_id=MID):
    """Appelle la vraie fonction ; renvoie (verdict, requêtes vues, kwargs du client)."""
    seen: list[httpx.Request] = []
    kwargs: list[dict] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    class Client(_REAL_CLIENT):
        def __init__(self, *args, **kw):
            kwargs.append(kw)
            super().__init__(*args, transport=httpx.MockTransport(record), **kw)

    with patch.object(mj.httpx, "AsyncClient", Client):
        verdict = _run(mj.check_mission_active(mission_id, url, ttl, bearer))
    return verdict, seen, kwargs


def _ok(**body):
    return lambda request: httpx.Response(200, json=body)


# --- Le jeton part, et seulement où il doit ------------------------------------------------------


def test_bearer_is_forwarded_exactly_on_https_get():
    verdict, seen, _ = _call(_ok(mission_id=MID, active=True))
    assert verdict == (True, "")
    assert [(r.method, str(r.url)) for r in seen] == [("GET", f"https://mission.interne/internal/missions/{MID}/active")]
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in str(seen[0].url)


def test_bearer_is_never_sent_over_plain_http():
    verdict, seen, _ = _call(_ok(mission_id=MID, active=True), url=HTTP)
    assert verdict == (True, "")
    assert "authorization" not in seen[0].headers


def test_without_bearer_the_old_unauthenticated_call_is_unchanged():
    verdict, seen, _ = _call(_ok(status="RUNNING"), bearer=None)
    assert verdict == (True, "")
    assert "authorization" not in seen[0].headers


def test_redirect_is_not_followed_and_the_token_goes_nowhere_else():
    def handler(request):
        if request.url.host == "mission.interne":
            return httpx.Response(302, headers={"location": "https://ailleurs.invalid/capture"})
        raise AssertionError("redirection suivie : le jeton est parti ailleurs")

    verdict, seen, kwargs = _call(handler)
    assert verdict == (False, "service_unavailable")
    assert len(seen) == 1
    assert kwargs[0]["follow_redirects"] is False


# --- Contrat courant : active strict, mission_id exact --------------------------------------------


def test_active_true_and_false_are_read_as_such():
    assert _call(_ok(mission_id=MID, active=True))[0] == (True, "")
    assert _call(_ok(mission_id=MID, active=False))[0] == (False, "mission_inactive")


@pytest.mark.parametrize(
    "body",
    [
        {"mission_id": MID, "active": "true"},
        {"mission_id": MID, "active": 1},
        {"mission_id": MID, "active": None},
        {"mission_id": MID, "active": "false"},
        {"active": True},
        {"mission_id": "mis_autre", "active": True},
        {"mission_id": None, "active": True},
        {"mission_id": MID.upper(), "active": True},
        # `active` présent mais invalide : l'ancien champ ne peut pas rattraper un corps ambigu.
        {"mission_id": MID, "active": "yes", "status": "RUNNING"},
        {"mission_id": "mis_autre", "active": True, "status": "RUNNING"},
    ],
)
def test_ambiguous_or_mismatched_body_fails_closed_never_active(body):
    verdict, _, _ = _call(_ok(**body))
    assert verdict == (False, "service_unavailable")


def test_non_object_body_fails_closed():
    assert _call(lambda r: httpx.Response(200, json=["active", True]))[0] == (False, "service_unavailable")
    assert _call(lambda r: httpx.Response(200, content=b"pas du json"))[0] == (False, "service_unavailable")


def test_active_false_wins_over_a_live_legacy_field():
    assert _call(_ok(mission_id=MID, active=False, status="RUNNING"))[0] == (False, "mission_inactive")


# --- Ancien contrat conservé ----------------------------------------------------------------------


@pytest.mark.parametrize("state", ["RUNNING", "waiting_human", "PAUSED"])
def test_legacy_live_states_still_active(state):
    assert _call(_ok(status=state))[0] == (True, "")
    mj._mission_status_cache.clear()
    assert _call(_ok(state=state))[0] == (True, "")


@pytest.mark.parametrize("body", [{"status": "ABORTED"}, {"state": "COMPLETED"}, {"status": ""}, {}])
def test_legacy_other_states_and_unknown_are_inactive(body):
    assert _call(_ok(**body))[0] == (False, "mission_inactive")


# --- Pannes : jamais une conclusion sur la mission -------------------------------------------------


@pytest.mark.parametrize("status", [401, 403, 404, 410, 500, 503])
def test_non_200_is_unavailable_not_inactive(status):
    assert _call(lambda r: httpx.Response(status, json={"error": "x"}))[0] == (False, "service_unavailable")


def test_transport_error_is_unavailable_and_message_never_logged(caplog):
    def handler(request):
        raise httpx.ConnectError(f"boom {TOKEN}")

    with caplog.at_level(logging.DEBUG):
        verdict, _, _ = _call(handler)
    assert verdict == (False, "service_unavailable")
    assert TOKEN not in caplog.text


def test_token_is_never_logged_on_any_path(caplog):
    cases = [
        _ok(mission_id=MID, active=True),
        _ok(mission_id=MID, active=False),
        _ok(mission_id="mis_autre", active=True),
        _ok(status="ABORTED"),
        lambda r: httpx.Response(401),
        lambda r: httpx.Response(302, headers={"location": "https://ailleurs.invalid/"}),
    ]
    with caplog.at_level(logging.DEBUG):
        for handler in cases:
            mj._mission_status_cache.clear()
            _call(handler)
    assert TOKEN not in caplog.text


# --- Cache et single-flight conservés -------------------------------------------------------------


def test_verdict_is_cached_per_mission_and_unavailable_is_cached_at_most_one_second():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"mission_id": MID, "active": True})

    class Client(_REAL_CLIENT):
        def __init__(self, *a, **k):
            super().__init__(*a, transport=httpx.MockTransport(handler), **k)

    async def twice():
        first = await mj.check_mission_active(MID, HTTPS, 30, TOKEN)
        second = await mj.check_mission_active(MID, HTTPS, 30, TOKEN)
        return first, second

    with patch.object(mj.httpx, "AsyncClient", Client):
        first, second = _run(twice())
    assert first == second == (True, "")
    assert len(calls) == 1

    mj._mission_status_cache.clear()
    _call(lambda r: httpx.Response(503), ttl=30)
    _, _, expires = mj._mission_status_cache[MID]
    assert expires - time.time() <= mj._MISSION_STATUS_ERROR_TTL + 0.5


def test_concurrent_callers_of_one_mission_make_one_outgoing_call():
    calls = []

    async def slow(request):
        calls.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"mission_id": MID, "active": True})

    class Client(_REAL_CLIENT):
        def __init__(self, *a, **k):
            super().__init__(*a, transport=httpx.MockTransport(slow), **k)

    async def many():
        return await asyncio.gather(*[mj.check_mission_active(MID, HTTPS, 30, TOKEN) for _ in range(6)])

    with patch.object(mj.httpx, "AsyncClient", Client):
        verdicts = _run(many())
    assert verdicts == [(True, "")] * 6
    assert len(calls) == 1


# --- Les deux appelants transmettent leur jeton ---------------------------------------------------


def test_pep_transport_passes_the_validated_jwt_to_the_status_callback():
    from mcp_vault.auth import middleware as m

    got = {}

    async def fake_status(mission_id, status_url_template, cache_ttl, bearer=None):
        got.update(mission_id=mission_id, url=status_url_template, bearer=bearer)
        return False, "mission_inactive"

    async def fake_validate(cache, call):
        return {"mission_id": MID, "tenant_id": "fge-a", "jti": "j", "component_id": {"vault": "x"}}

    settings = SimpleNamespace(
        resolved_mission_aud="x",
        mcp_component_kind="vault",
        mission_token_leeway_seconds=10,
        mission_status_url=HTTPS,
        mission_status_cache_ttl=0,
    )
    pep = m.AuthMiddleware.__new__(m.AuthMiddleware)
    with (
        patch.object(mj, "get_jwks_cache", return_value=object()),
        patch.object(mj, "valider_hors_boucle", fake_validate),
        patch.object(mj, "check_mission_active", fake_status),
    ):
        info, refusal = _run(pep._validate_mission_jwt(TOKEN, settings))
    assert info is None and refusal[0] == 403
    assert got == {"mission_id": MID, "url": HTTPS, "bearer": TOKEN}
