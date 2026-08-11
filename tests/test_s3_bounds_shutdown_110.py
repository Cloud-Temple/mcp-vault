# -*- coding: utf-8 -*-
"""
Tests #110 lot 1 — bornes réseau S3 et chemin d'arrêt réellement exécuté.

Deux défauts corrigés ici :

1. **Appels S3 non bornés** : les clients boto3 étaient créés sans
   `connect_timeout`/`read_timeout` et avec `max_attempts` (retries APRÈS la
   première tentative). Un appel lent pouvait donc bloquer plusieurs minutes.
2. **Chemin d'arrêt mort** : `vault_shutdown()` était appelé APRÈS
   `server.serve()`. uvicorn ré-émet le SIGTERM capturé une fois son arrêt
   interne terminé — ce code ne s'exécutait donc jamais sur un `docker stop`.
   L'arrêt est désormais porté par le lifespan ASGI, composé AUTOUR du lifespan
   de FastMCP (qui doit être préservé, sinon toute requête MCP échoue).

Preuve RED (état pré-correctif) : les tests de bornes échouent (aucun timeout
dans la config, `max_attempts` au lieu de `total_max_attempts`), et
`test_lifespan_runs_shutdown_even_if_serve_never_returns` échoue puisque
l'arrêt n'est pas dans le lifespan.
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# 1. Bornes réseau S3
# =============================================================================

def _settings(connect=5, read=30, attempts=2):
    s = MagicMock()
    s.s3_region_name = "fr1"
    s.s3_endpoint_url = "https://s3.example.invalid"
    s.s3_access_key_id = "k"
    s.s3_secret_access_key = "s"
    s.s3_connect_timeout = connect
    s.s3_read_timeout = read
    s.s3_max_attempts = attempts
    return s


@pytest.mark.parametrize("getter", ["get_s3_data_client", "get_s3_meta_client"])
def test_both_clients_carry_bounded_timeouts_from_settings(getter):
    """Les DEUX clients (data SigV2 et meta SigV4) portent les bornes des settings.

    RED avant #110 : aucun timeout dans la Config → attributs à None.
    """
    from mcp_vault import s3_client

    s3_client.reset_clients()
    with patch.object(s3_client, "get_settings", return_value=_settings(3, 17, 2)):
        client = getattr(s3_client, getter)()
    cfg = client.meta.config
    assert cfg.connect_timeout == 3, "connect_timeout non câblé depuis les settings"
    assert cfg.read_timeout == 17, "read_timeout non câblé depuis les settings"
    s3_client.reset_clients()


@pytest.mark.parametrize("getter", ["get_s3_data_client", "get_s3_meta_client"])
def test_retries_use_total_max_attempts_not_max_attempts(getter):
    """`S3_MAX_ATTEMPTS=2` doit signifier 2 appels réseau AU TOTAL.

    NON-COMPLAISANCE : botocore interprète `max_attempts=2` comme 2 retries
    APRÈS la tentative initiale (3 appels). Le test pin donc explicitement
    `total_max_attempts == 2` et le mode "standard" (plus prévisible que
    l'adaptatif ; le backoff avec jitter subsiste).
    """
    from mcp_vault import s3_client

    s3_client.reset_clients()
    with patch.object(s3_client, "get_settings", return_value=_settings(attempts=2)):
        client = getattr(s3_client, getter)()
    retries = client.meta.config.retries
    assert retries["total_max_attempts"] == 2, f"attendu 2 tentatives totales : {retries}"
    assert retries["mode"] == "standard", f"mode adaptatif moins prévisible : {retries}"
    s3_client.reset_clients()


def test_create_s3_clients_shares_the_same_bounded_factory():
    """La fabrique non-singleton ne doit pas repartir avec les défauts botocore."""
    from mcp_vault import s3_client

    with patch.object(s3_client, "get_settings", return_value=_settings(4, 11, 3)):
        data, meta = s3_client.create_s3_clients(
            "https://s3.example.invalid", "k", "s", region="fr1")
    for client in (data, meta):
        assert client.meta.config.connect_timeout == 4
        assert client.meta.config.read_timeout == 11
        assert client.meta.config.retries["total_max_attempts"] == 3


@pytest.mark.parametrize("kwargs,expected_key", [
    ({"s3_connect_timeout": 0}, "S3_CONNECT_TIMEOUT"),
    ({"s3_connect_timeout": -1}, "S3_CONNECT_TIMEOUT"),
    ({"s3_read_timeout": 0}, "S3_READ_TIMEOUT"),
    ({"s3_max_attempts": 0}, "S3_MAX_ATTEMPTS"),
])
def test_invalid_bounds_are_refused_at_boot(kwargs, expected_key):
    """Une borne nulle/négative = appels non bornés → refus de démarrer."""
    from mcp_vault.config import Settings

    s = Settings(admin_bootstrap_key="Test-Bootstrap-Key-2026-Pour-Tests!!", **kwargs)
    ok, msg = s.check_s3_timeouts()
    assert ok is False and expected_key in msg, f"{kwargs} devrait être refusé : {msg}"


def test_default_bounds_are_valid():
    """Non-complaisance : les défauts livrés doivent passer la validation."""
    from mcp_vault.config import Settings

    s = Settings(admin_bootstrap_key="Test-Bootstrap-Key-2026-Pour-Tests!!")
    assert s.check_s3_timeouts() == (True, "")
    assert (s.s3_connect_timeout, s.s3_read_timeout, s.s3_max_attempts) == (5, 30, 2)


# =============================================================================
# 2. Chemin d'arrêt : lifespan composé
# =============================================================================

class _FakeRouter:
    def __init__(self, lifespan_context):
        self.lifespan_context = lifespan_context


class _FakeApp:
    """App minimale exposant `router.lifespan_context`, comme Starlette."""

    def __init__(self, lifespan_context):
        self.router = _FakeRouter(lifespan_context)


def _fastmcp_lifespan_spy(calls):
    """Imite le lifespan de FastMCP (session_manager.run) et trace son passage."""

    @asynccontextmanager
    async def _lifespan(app):
        calls.append("fastmcp_start")
        try:
            yield {"session_manager": "initialized"}
        finally:
            calls.append("fastmcp_stop")

    return _lifespan


import contextlib


@contextlib.contextmanager
def _composed_lifespan(app_calls, startup=None, shutdown=None):
    """Installe le lifespan composé, patchs ACTIFS pendant tout l'exercice.

    Les patchs portent sur les attributs du module `mcp_vault.lifecycle` : le
    lifespan composé fait son `from .lifecycle import ...` À L'APPEL, donc il
    voit bien les mocks. (Un `patch.dict(sys.modules)` refermé avant l'exercice
    laisserait tourner le VRAI startup — piège rencontré en écrivant ce test.)
    """
    from mcp_vault import server
    import mcp_vault.lifecycle as lifecycle_mod

    app = _FakeApp(_fastmcp_lifespan_spy(app_calls))
    startup = startup if startup is not None else AsyncMock(return_value=True)
    shutdown = shutdown if shutdown is not None else AsyncMock()
    with patch.object(lifecycle_mod, "vault_startup", startup), \
         patch.object(lifecycle_mod, "vault_shutdown", shutdown):
        server._install_vault_lifespan(app)
        yield app.router.lifespan_context(app), startup, shutdown


def test_lifespan_preserves_fastmcp_and_orders_startup_shutdown():
    """Ordre imposé : vault_startup → FastMCP start → service → FastMCP stop → shutdown.

    NON-COMPLAISANCE : si le lifespan FastMCP était REMPLACÉ (et non composé),
    `fastmcp_start` n'apparaîtrait pas — et en production toute requête MCP
    échouerait sur « Task group is not initialized ».
    """
    calls = []
    with _composed_lifespan(calls) as (ctx, startup, shutdown):
        async def _exercise():
            async with ctx as state:
                calls.append("serving")
                assert state == {"session_manager": "initialized"}, \
                    "l'état du lifespan FastMCP doit être propagé"
        _run(_exercise())
        assert calls == ["fastmcp_start", "serving", "fastmcp_stop"], calls
        startup.assert_awaited_once()
        shutdown.assert_awaited_once_with(skip_upload=False)


def test_lifespan_runs_shutdown_even_if_serve_never_returns():
    """Le cœur du défaut #110 : l'arrêt s'exécute dans la phase de shutdown ASGI.

    On simule l'arrêt d'uvicorn (sortie du contexte) : `vault_shutdown` DOIT
    avoir été exécuté à ce moment-là, sans dépendre d'un code après `serve()`.
    """
    calls = []
    with _composed_lifespan(calls) as (ctx, _startup, shutdown):
        async def _exercise():
            async with ctx:
                shutdown.assert_not_awaited()  # pas encore : le service tourne
        _run(_exercise())
        shutdown.assert_awaited_once()


def test_degraded_mode_when_startup_raises_forces_skip_upload():
    """`vault_startup` qui LÈVE → service démarré ET skip_upload=True.

    Invariant #94 : un démarrage non abouti ne doit jamais déclencher l'upload
    final (il écraserait une sauvegarde S3 valide par un état local incomplet).
    """
    calls = []
    startup = AsyncMock(side_effect=RuntimeError("OpenBao KO"))
    with _composed_lifespan(calls, startup=startup) as (ctx, _s, shutdown):
        async def _exercise():
            async with ctx:
                calls.append("serving")
        _run(_exercise())
        assert "serving" in calls, "le service doit démarrer en mode dégradé"
        assert "fastmcp_start" in calls, \
            "le lifespan FastMCP doit tourner malgré le mode dégradé"
        shutdown.assert_awaited_once_with(skip_upload=True)


def test_degraded_mode_when_startup_returns_false_forces_skip_upload():
    calls = []
    startup = AsyncMock(return_value=False)
    with _composed_lifespan(calls, startup=startup) as (ctx, _s, shutdown):
        async def _exercise():
            async with ctx:
                pass
        _run(_exercise())
        shutdown.assert_awaited_once_with(skip_upload=True)


def test_shutdown_error_does_not_mask_service_stop():
    """Une exception dans vault_shutdown ne doit pas remonter au serveur ASGI."""
    calls = []
    shutdown = AsyncMock(side_effect=RuntimeError("S3 down"))
    with _composed_lifespan(calls, shutdown=shutdown) as (ctx, _s, _sd):
        async def _exercise():
            async with ctx:
                pass
        _run(_exercise())  # ne doit pas lever
        assert calls == ["fastmcp_start", "fastmcp_stop"]


# =============================================================================
# 3. Idempotence de l'arrêt (lifespan + filet post-serve)
# =============================================================================

def test_real_asgi_stack_runs_lifespan_startup_and_shutdown():
    """SEAM RÉEL (revue pré-commit) : on construit la VRAIE stack via
    `create_app()` et on pilote le protocole ASGI `lifespan`.

    Prouve ce que le test synthétique ne prouvait pas : le wrapper est bien
    installé sur l'application Starlette produite par FastMCP, et le scope
    `lifespan` traverse les cinq middlewares (Pki → Admin → Health → Auth →
    Logging) jusqu'à elle. Sans la composition, `lifespan.startup.complete`
    n'arriverait pas — ou les requêtes MCP casseraient en production.
    """
    from mcp_vault import server
    import mcp_vault.lifecycle as lifecycle_mod

    startup = AsyncMock(return_value=True)
    shutdown = AsyncMock()
    with patch.object(lifecycle_mod, "vault_startup", startup), \
         patch.object(lifecycle_mod, "vault_shutdown", shutdown):
        app = server.create_app()

        received = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent = []

        async def _receive():
            return received.pop(0)

        async def _send(message):
            sent.append(message["type"])

        _run(app({"type": "lifespan", "asgi": {"version": "3.0"}}, _receive, _send))

    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"], sent
    startup.assert_awaited_once()
    shutdown.assert_awaited_once_with(skip_upload=False)


def test_shutdown_is_replayable_after_cancellation():
    """L'idempotence ne doit pas devenir un verrou définitif (revue pré-commit).

    Si l'arrêt est ANNULÉ avant d'avoir scellé quoi que ce soit, un appel
    ultérieur (le filet de `server.main()`) doit rejouer la séquence — sinon le
    coffre resterait non scellé, sans plus aucune chance d'arrêt propre.
    """
    from mcp_vault import lifecycle

    lifecycle._reset_shutdown_state()
    seal = AsyncMock(return_value={"status": "sealed"})

    async def _cancelled_stop():
        raise asyncio.CancelledError()

    fake_s3_sync = MagicMock(stop_periodic_sync=AsyncMock(side_effect=_cancelled_stop),
                             upload_to_s3=AsyncMock(return_value=True))
    fake_openbao_lc = MagicMock(seal_vault=seal, clear_in_memory_keys=MagicMock())
    fake_manager = MagicMock(stop_openbao=AsyncMock())

    with patch.dict(sys.modules, {
        "mcp_vault.s3_sync": fake_s3_sync,
        "mcp_vault.openbao.lifecycle": fake_openbao_lc,
        "mcp_vault.openbao.manager": fake_manager,
    }):
        # 1er appel : annulé pendant l'arrêt de la sync — rien n'est scellé.
        with pytest.raises(asyncio.CancelledError):
            _run(lifecycle.vault_shutdown(skip_upload=True))
        assert seal.await_count == 0, "rien ne doit avoir été scellé"

        # 2e appel : la séquence DOIT être rejouée (sync qui n'annule plus).
        fake_s3_sync.stop_periodic_sync = AsyncMock()
        _run(lifecycle.vault_shutdown(skip_upload=True))

    assert seal.await_count == 1, \
        "l'arrêt est resté verrouillé après annulation — coffre jamais scellé !"
    lifecycle._reset_shutdown_state()


def test_new_startup_rearms_shutdown():
    """Deux cycles de vie dans le même processus : le second doit pouvoir s'arrêter."""
    from mcp_vault import lifecycle

    lifecycle._reset_shutdown_state()
    lifecycle._shutdown_done = True          # état après un premier cycle complet
    with patch.object(lifecycle, "get_settings", side_effect=RuntimeError("stop ici")):
        with pytest.raises(RuntimeError):
            _run(lifecycle.vault_startup())
    assert lifecycle._shutdown_done is False, \
        "vault_startup() doit réarmer l'arrêt pour le nouveau cycle"
    lifecycle._reset_shutdown_state()


def test_compose_declares_a_stop_grace_period_covering_shutdown():
    """Le délai de grâce Docker doit couvrir la séquence d'arrêt (revue pré-commit).

    Le défaut Docker (10 s) tuerait le processus avant le seal et la sauvegarde
    finale, maintenant que l'arrêt s'exécute réellement.
    """
    import yaml

    root = os.path.join(os.path.dirname(__file__), "..")
    with open(os.path.join(root, "docker-compose.yml")) as fh:
        compose = yaml.safe_load(fh)

    grace = compose["services"]["mcp-vault"].get("stop_grace_period")
    assert grace, "mcp-vault doit déclarer un stop_grace_period explicite"
    seconds = int(str(grace).rstrip("s"))
    assert seconds >= 90, (
        f"stop_grace_period={grace} trop court : doit couvrir pré-drain uvicorn "
        "+ seal + sauvegarde finale S3 bornée + arrêt OpenBao"
    )


def test_vault_shutdown_is_idempotent():
    """Le lifespan ET le filet de server.main() peuvent appeler l'arrêt.

    NON-COMPLAISANCE : on vérifie qu'un SECOND appel ne rejoue NI le seal NI
    l'upload final (un upload après seal réécrirait l'archive sans raison).
    """
    from mcp_vault import lifecycle

    lifecycle._reset_shutdown_state_for_tests()
    stop_sync = AsyncMock()
    seal = AsyncMock(return_value={"status": "sealed"})
    upload = AsyncMock(return_value=True)
    stop_openbao = AsyncMock()

    fake_s3_sync = MagicMock(stop_periodic_sync=stop_sync, upload_to_s3=upload)
    fake_openbao_lc = MagicMock(seal_vault=seal, clear_in_memory_keys=MagicMock())
    fake_manager = MagicMock(stop_openbao=stop_openbao)

    with patch.dict(sys.modules, {
        "mcp_vault.s3_sync": fake_s3_sync,
        "mcp_vault.openbao.lifecycle": fake_openbao_lc,
        "mcp_vault.openbao.manager": fake_manager,
    }):
        _run(lifecycle.vault_shutdown(skip_upload=False))
        first_seal = seal.await_count
        first_upload = upload.await_count
        _run(lifecycle.vault_shutdown(skip_upload=False))

    assert first_seal == 1, "le premier appel doit sceller"
    assert seal.await_count == first_seal, "le second appel a rejoué le seal !"
    assert upload.await_count == first_upload, "le second appel a rejoué l'upload !"
    lifecycle._reset_shutdown_state_for_tests()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
