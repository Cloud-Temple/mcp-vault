"""Limite réglable des lectures OpenBao simultanées (storage/reader.py).

Contrat testé :
- `METADATA_READER_CONCURRENCY` vaut 4 par défaut, soit la limite figée
  jusqu'ici, et refuse toute valeur hors de 1 à 32 au démarrage ;
- le sémaphore est construit une seule fois depuis la configuration, même
  quand plusieurs threads font la première lecture en même temps ;
- avec N configuré, N lectures bloquées laissent la N+1e attendre 1 s puis
  échouer en `reader_admission_timeout`, sans appel HTTP ; les places reviennent
  ensuite ;
- sur le flux HTTP réel, ce refus devient un 503 et la ligne
  `raison=reader_admission_timeout` de l'admission reste journalisée ;
- le login PG gardé en mémoire ne prend aucune place du lecteur sur le chemin
  des requêtes, et sa relecture de fond passe sur sa place dédiée quelle que
  soit la valeur de N.

Aucun OpenBao réel : `httpx.Client` est remplacé par un faux coffre qui bloque
les lectures propriétaire sur un événement et rend le login PG tout de suite.
Le vrai `_request`, le vrai `preload_owners`, le vrai `admitted_call` et le
vrai `connection()` sont exercés. Les N retenus (2 et 6) encadrent l'ancienne
valeur figée : un sémaphore resté à 4 fait échouer les deux cas.
"""
import asyncio
import json
import logging
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from mcp_vault.storage.postgres import MetadataUnavailable
from tests.test_pg_login_refresh import TOKEN, FakeServer, login_value, pg  # noqa: F401

OWNER = {"created_by": "alice"}


class FakeBao:
    """Faux OpenBao : lectures propriétaire bloquées sur `gate`, login immédiat."""

    def __init__(self):
        self.gate = threading.Event()
        self.lock = threading.Lock()
        self.owner_calls = 0
        self.login_calls = 0
        self.entered = threading.Semaphore(0)
        self.threads = []

    def drain(self):
        """Libère et termine les lectures tenues, même après un test en échec."""
        self.gate.set()
        for thread in self.threads:
            thread.join(5)
        assert not any(t.is_alive() for t in self.threads), "lecture propriétaire encore en vol"

    def client(self, *args, **kwargs):
        return _Client(self)


class _Client:
    def __init__(self, bao):
        self.bao = bao

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @contextmanager
    def stream(self, method, url, headers):
        bao = self.bao
        if url.endswith("/data/app/connection"):
            with bao.lock:
                bao.login_calls += 1
            body = {"data": {"data": login_value()}}
        else:
            with bao.lock:
                bao.owner_calls += 1
            bao.entered.release()
            if not bao.gate.wait(10):
                raise AssertionError("lecture propriétaire jamais libérée par le test")
            body = {"data": {"data": OWNER}}
        payload = json.dumps(body).encode()
        yield SimpleNamespace(status_code=200, iter_bytes=lambda: iter([payload]))


@pytest.fixture(autouse=True)
def _settings_isolation():
    from mcp_vault.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def bao(monkeypatch):
    import httpx
    from mcp_vault.openbao import manager
    fake = FakeBao()
    monkeypatch.setattr(httpx, "Client", fake.client)
    monkeypatch.setattr(manager, "get_hvac_client", lambda: SimpleNamespace(token="unit-token"))
    yield fake
    fake.drain()


def configure(monkeypatch, value):
    """Réglage puis sémaphore neuf, comme au démarrage d'un processus."""
    from mcp_vault.config import get_settings
    from mcp_vault.storage import reader
    if value is None:
        monkeypatch.delenv("METADATA_READER_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("METADATA_READER_CONCURRENCY", str(value))
    get_settings.cache_clear()
    monkeypatch.setattr(reader, "_reads", None)


def admitted(semaphore, count):
    """Nombre de places prises sans attendre, puis rendues."""
    taken = 0
    while taken <= count and semaphore.acquire(blocking=False):
        taken += 1
    for _ in range(taken):
        semaphore.release()
    return taken


def hold(bao, n):
    """N lectures propriétaire réelles, bloquées dans OpenBao, places tenues."""
    from mcp_vault.storage import reader
    results = []

    def read(i):
        try:
            results.append(reader.owner_metadata(f"coffre-{i}"))
        except BaseException as exc:  # noqa: BLE001, examinée par le test
            results.append(exc)
    threads = [threading.Thread(target=read, args=(i,), daemon=True) for i in range(n)]
    bao.threads.extend(threads)
    for thread in threads:
        thread.start()
    for _ in range(n):
        assert bao.entered.acquire(timeout=5), "les N lectures n'ont pas toutes obtenu une place"
    return threads, results


def release(bao, threads, results, n):
    bao.drain()
    assert results == [OWNER] * n


# ── Réglage ──────────────────────────────────────────────────────────────────

def test_defaut_4_places_comme_la_limite_figee(monkeypatch):
    from mcp_vault.config import get_settings
    from mcp_vault.storage import reader
    configure(monkeypatch, None)
    assert get_settings().metadata_reader_concurrency == 4
    assert admitted(reader.slots(), 10) == 4


@pytest.mark.parametrize("value", ["0", "-1", "33", "4.5", "beaucoup"])
def test_valeur_hors_plage_refusee_au_demarrage(monkeypatch, value):
    from mcp_vault.config import get_settings
    configure(monkeypatch, value)
    with pytest.raises(ValidationError) as exc:
        get_settings()
    assert "metadata_reader_concurrency" in str(exc.value)


@pytest.mark.parametrize("value", [1, 32])
def test_bornes_acceptees_et_appliquees(monkeypatch, value):
    from mcp_vault.storage import reader
    configure(monkeypatch, value)
    assert admitted(reader.slots(), 40) == value


def test_semaphore_construit_une_seule_fois_sous_concurrence(monkeypatch):
    """Huit premières lectures simultanées : une seule lecture de la config, un seul objet."""
    from mcp_vault.config import get_settings
    from mcp_vault.storage import reader
    configure(monkeypatch, 3)
    real, calls = reader.get_settings, []

    def slow_settings():
        calls.append(1)
        time.sleep(0.05)  # élargit la fenêtre de course qu'un verrou absent laisserait
        return real()
    monkeypatch.setattr(reader, "get_settings", slow_settings)
    barrier, built = threading.Barrier(8), []

    def first_use():
        barrier.wait()
        built.append(reader.slots())
    threads = [threading.Thread(target=first_use) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert len(calls) == 1 and len(built) == 8 and all(s is built[0] for s in built)
    assert admitted(built[0], 10) == 3
    # Le réglage est lu une fois par processus : le changer exige un redémarrage.
    monkeypatch.setenv("METADATA_READER_CONCURRENCY", "7")
    get_settings.cache_clear()
    assert reader.slots() is built[0]


# ── Admission des lectures ───────────────────────────────────────────────────

@pytest.mark.parametrize("n", [2, 6])
def test_n_plus_unieme_lecture_attend_puis_reader_admission_timeout(bao, monkeypatch, n):
    from mcp_vault.storage import reader
    configure(monkeypatch, n)
    threads, results = hold(bao, n)
    started = time.monotonic()
    with pytest.raises(MetadataUnavailable) as exc:
        reader.owner_metadata("coffre-en-trop")
    waited = time.monotonic() - started
    assert exc.value.reason == "reader_admission_timeout"
    # Refus sur l'attente d'1 s, bien avant l'échéance de 5 s de la lecture.
    assert 0.9 <= waited < 4.5, waited
    assert bao.owner_calls == n, "la lecture refusée ne doit jamais atteindre OpenBao"
    release(bao, threads, results, n)
    # Toutes les places sont rendues : N nouvelles prises immédiates, pas une de plus.
    assert admitted(reader.slots(), n + 5) == n
    assert reader.owner_metadata("coffre-apres") == OWNER


class SpySemaphore:
    """Enveloppe le vrai sémaphore pour signaler le premier refus."""

    def __init__(self, inner):
        self.inner, self.refused = inner, threading.Event()

    def acquire(self, *args, **kwargs):
        ok = self.inner.acquire(*args, **kwargs)
        if not ok:
            self.refused.set()
        return ok

    def release(self):
        self.inner.release()


def test_flux_http_lot_de_n_plus_un_coffres_503_et_raison_journalisee(bao, pg, monkeypatch, caplog):
    """preload_owners sur N+1 coffres : 503 et la ligne `raison=` de l'admission."""
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage import admission, reader
    n = 2
    configure(monkeypatch, n)
    spy = SpySemaphore(reader.slots())
    monkeypatch.setattr(reader, "_reads", spy)
    ids = [f"coffre-{i}" for i in range(n + 1)]

    async def admit(raw):
        return {"owners": {}}
    monkeypatch.setattr(admission, "admit", admit)

    def unblock():
        # Libère les N lectures tenues seulement après le refus de la N+1e.
        if spy.refused.wait(5):
            bao.gate.set()
    watcher = threading.Thread(target=unblock, daemon=True)
    watcher.start()

    async def endpoint(scope, receive, send):
        await admission.preload_owners(ids, batch=True)
        raise AssertionError("le lot aurait dû être refusé")

    sent = []

    async def send(message):
        sent.append(message)

    async def run():
        token = current_token_info.set({"client_name": "alice", "permissions": ["read"],
                                        "allowed_resources": ids, "auth_type": "bearer"})
        try:
            await admission.admitted_call({"headers": [(b"authorization", b"Bearer x")]}, None, send, endpoint)
        finally:
            current_token_info.reset(token)
    with caplog.at_level(logging.WARNING):
        asyncio.run(run())
    watcher.join(5)
    assert spy.refused.is_set() and bao.owner_calls == n
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 503
    assert any("raison=reader_admission_timeout" in r.getMessage() for r in caplog.records)


# ── Login PG ─────────────────────────────────────────────────────────────────

@pytest.fixture
def pg_server(pg, monkeypatch):  # noqa: F811
    """Faux PostgreSQL de #203, mais le login est lu par le vrai credentials()."""
    import psycopg
    from mcp_vault.storage import audit_schema, postgres
    fake = FakeServer()
    monkeypatch.setattr(psycopg, "connect", fake.connect)
    monkeypatch.setattr(audit_schema, "verify", lambda conn, settings: None)
    monkeypatch.setattr(postgres, "_slots", threading.BoundedSemaphore(4))
    return fake


@pytest.mark.parametrize("n", [2, 6])
def test_login_en_memoire_ne_prend_aucune_place_du_lecteur(pg_server, bao, monkeypatch, n):
    """Lecteur saturé par N lectures propriétaire : admit() passe avec le login en mémoire."""
    from mcp_vault.storage import admission, pg_login
    from mcp_vault.storage.postgres import connection
    configure(monkeypatch, n)
    assert pg_login.start() is True
    assert bao.login_calls == 1
    threads, results = hold(bao, n)
    facts = asyncio.run(admission.admit(TOKEN))
    assert facts["actor_revision"] == 1
    assert bao.login_calls == 1, "le chemin des requêtes ne doit pas relire le login"
    # Contre-épreuve : la même connexion qui relit le coffre attend bien une place.
    with pg_login.fresh_reads(), pytest.raises(MetadataUnavailable) as exc:
        with connection():
            pass
    assert exc.value.reason == "reader_admission_timeout"
    assert bao.login_calls == 1
    release(bao, threads, results, n)


@pytest.mark.parametrize("n", [2, 6])
def test_relecture_de_fond_du_login_ne_depend_pas_du_reglage(pg, bao, monkeypatch, n):  # noqa: F811
    """N places communes prises : lecture initiale et relecture du login passent
    sur leur place dédiée, alors qu'une N+1e lecture propriétaire est refusée."""
    from mcp_vault.storage import pg_login, reader
    configure(monkeypatch, n)
    threads, results = hold(bao, n)
    assert pg_login.start() is True
    memory = pg_login.active()
    memory.refresh_once()
    assert memory.last_error == "" and memory.current().value == login_value()
    assert bao.login_calls == 2
    with pytest.raises(MetadataUnavailable) as exc:
        reader.owner_metadata("coffre-en-trop")
    assert exc.value.reason == "reader_admission_timeout"
    assert bao.owner_calls == n
    release(bao, threads, results, n)
