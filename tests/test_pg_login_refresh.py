"""Login PG applicatif gardé en mémoire et relu en fond (storage/pg_login.py).

Contrat testé :
- lecture au démarrage, service prêt seulement après une lecture réussie ;
- relecture de fond toutes les 30 s, les requêtes lisent la mémoire ;
- validité 60 s après le début de la dernière lecture réussie, puis refus fermé ;
- après un échec, réessai à 5 s sans rien prolonger ; refus explicite du coffre
  = oubli immédiat ;
- échec de connexion PG ou identité SQL inattendue = relecture immédiate, une
  seule pour N refus ; un login plus récent n'est jamais effacé ; la requête
  n'est pas retentée ;
- une boucle de fond morte n'est jamais relancée : refus fermé à l'expiration ;
- réglages à 0 = lecture du coffre à chaque connexion (retour arrière) ;
- les faits du token restent relus dans PostgreSQL à chaque requête.

Aucun PostgreSQL ni OpenBao réel : `psycopg.connect` est remplacé par un faux
serveur qui répond aux contrôles de `postgres.connection()`, et la lecture du
coffre par un compteur. Le vrai `connection()`, le vrai `admit()` et la vraie
boucle de fond sont exercés.
"""
import asyncio
import hashlib
import logging
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mcp_vault.storage.postgres import MetadataUnavailable

APP_PASSWORD = "app-password-synthetic"
PROVISIONER_PASSWORD = "provisioner-password-synthetic"
TOKEN = "business-token"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()


def login_value(password=APP_PASSWORD, user="vault_app"):
    return {"host": "pg.test", "port": "5432", "dbname": "vault", "user": user, "password": password}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Reads:
    """Faux coffre : rend une suite de valeurs ou lève une suite d'erreurs."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.count = 0
        self.times = []

    def __call__(self):
        self.count += 1
        self.times.append(time.monotonic())
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def wait_until(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def cache(read, clock=None, **kw):
    from mcp_vault.storage.pg_login import LoginCache
    options = {"refresh": 30, "validity": 60, "retry": 5}
    options.update(kw)
    return LoginCache(read, clock=clock or Clock(), **options)


# =============================================================================
# 1) Cœur du modèle, horloge simulée
# =============================================================================

def test_lecture_initiale_puis_memoire_sans_relire_le_coffre():
    reads = Reads(login_value())
    c = cache(reads)
    assert c.refresh_once() == 30
    for _ in range(50):
        assert c.current().value == login_value()
    assert reads.count == 1


def test_avant_toute_lecture_reussie_refus_ferme():
    c = cache(Reads(MetadataUnavailable("vault_unavailable")))
    with pytest.raises(MetadataUnavailable, match="login_unavailable"):
        c.current()
    assert c.refresh_once() == 5
    with pytest.raises(MetadataUnavailable, match="login_unavailable"):
        c.current()


def test_rotation_le_login_relu_remplace_l_ancien():
    reads = Reads(login_value("old"), login_value("new"))
    clock = Clock()
    c = cache(reads, clock)
    c.refresh_once()
    first = c.current()
    clock.now += 30
    c.refresh_once()
    second = c.current()
    assert first.value["password"] == "old" and second.value["password"] == "new"
    assert second.generation == first.generation + 1


@pytest.mark.parametrize("reason", ["vault_unavailable", "backend_unavailable", "reader_admission_timeout",
                                    "reader_deadline", "metadata_corrupt"])
def test_panne_du_coffre_sert_jusqu_a_60s_puis_refus_ferme(reason):
    clock = Clock()
    reads = Reads(login_value(), MetadataUnavailable(reason))
    c = cache(reads, clock)
    c.refresh_once()
    # Relecture de fond à 30 s, puis réessais toutes les 5 s : aucun ne prolonge.
    clock.now += 30
    for _ in range(5):
        assert c.refresh_once() == 5
        assert c.current().value == login_value()
        clock.now += 5
    clock.now = 1000.0 + 59.999
    assert c.current().value == login_value()
    clock.now = 1000.0 + 60
    with pytest.raises(MetadataUnavailable, match="login_expired"):
        c.current()
    # Aucun délai de grâce supplémentaire.
    clock.now += 1000
    with pytest.raises(MetadataUnavailable, match="login_expired"):
        c.current()


def test_validite_comptee_depuis_le_debut_de_la_lecture():
    """Une lecture lente ne rallonge pas la validité de sa propre durée."""
    clock = Clock()

    def slow_read():
        clock.now += 4
        return login_value()
    c = cache(slow_read, clock)
    c.refresh_once()
    clock.now = 1000.0 + 60
    with pytest.raises(MetadataUnavailable, match="login_expired"):
        c.current()


def test_reprise_apres_expiration_sur_lecture_reussie():
    clock = Clock()
    reads = Reads(login_value(), MetadataUnavailable("backend_unavailable"), login_value("rotated"))
    c = cache(reads, clock)
    c.refresh_once()
    clock.now += 61
    c.refresh_once()
    with pytest.raises(MetadataUnavailable):
        c.current()
    c.refresh_once()
    assert c.current().value["password"] == "rotated"


@pytest.mark.parametrize("reason", ["backend_denied", "metadata_absent_confirmed", "connection_invalid"])
def test_refus_explicite_du_coffre_oublie_le_login_tout_de_suite(reason):
    clock = Clock()
    c = cache(Reads(login_value(), MetadataUnavailable(reason)), clock)
    c.refresh_once()
    clock.now += 30
    assert c.refresh_once() == 5
    # Encore 30 s de validité théorique : le refus explicite l'emporte.
    with pytest.raises(MetadataUnavailable, match="login_refused"):
        c.current()


def test_identite_inattendue_oublie_le_login_et_reveille_la_boucle():
    c = cache(Reads(login_value()))
    c.refresh_once()
    login = c.current()
    assert c.report_failure(login, forget=True) is True
    with pytest.raises(MetadataUnavailable, match="login_refused"):
        c.current()
    assert c._wake.is_set()


def test_echec_de_connexion_reveille_sans_oublier():
    c = cache(Reads(login_value()))
    c.refresh_once()
    login = c.current()
    assert c.report_failure(login, forget=False) is True
    assert c.current() is login
    assert c._wake.is_set()


def test_un_login_plus_recent_n_est_jamais_efface():
    clock = Clock()
    c = cache(Reads(login_value("old"), login_value("new")), clock)
    c.refresh_once()
    old = c.current()
    c.refresh_once()
    assert c.report_failure(old, forget=True) is False
    assert c.current().value["password"] == "new"
    assert not c._wake.is_set()


def test_repr_du_login_sans_secret():
    c = cache(Reads(login_value()))
    c.refresh_once()
    assert APP_PASSWORD not in repr(c.current())


# =============================================================================
# 2) Boucle de fond réelle (intervalles courts)
# =============================================================================

def test_relecture_de_fond_sans_aucune_requete():
    from mcp_vault.storage.pg_login import LoginCache
    reads = Reads(*[login_value(f"p{i}") for i in range(50)])
    c = LoginCache(reads, refresh=0.05, validity=0.5, retry=0.02, spacing=0)
    try:
        assert c.start() is True
        assert wait_until(lambda: reads.count >= 4), "aucune relecture de fond"
        assert c.current().value["password"] != "p0"
    finally:
        assert c.stop()


def test_n_refus_simultanes_donnent_une_seule_lecture():
    """Le premier refus déclenche la lecture ; les 19 autres arrivent PENDANT
    cette lecture, avec le même login. Une seule lecture doit en résulter."""
    from mcp_vault.storage.pg_login import LoginCache
    entered, release = threading.Event(), threading.Event()
    values = iter([login_value("old"), login_value("new"), login_value("third")])
    reads = []

    def read():
        reads.append(1)
        if len(reads) == 2:
            entered.set()
            release.wait(5)
        return next(values)
    c = LoginCache(read, refresh=100, validity=200, retry=50, spacing=0)
    try:
        c.start()
        login = c.current()
        c.report_failure(login, forget=False)
        assert entered.wait(2)
        barrier = threading.Barrier(19)

        def refuse():
            barrier.wait()
            c.report_failure(login, forget=False)
        threads = [threading.Thread(target=refuse) for _ in range(19)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        release.set()
        assert wait_until(lambda: c.current().value["password"] == "new")
        # Côté vert, aucune lecture ne peut suivre : l'attente ne masque rien.
        assert not wait_until(lambda: len(reads) > 2, timeout=0.5), f"{len(reads)} lectures"
    finally:
        release.set()
        assert c.stop()


def test_intervalle_minimal_entre_deux_lectures_declenchees():
    from mcp_vault.storage.pg_login import LoginCache
    reads = Reads(login_value(), MetadataUnavailable("backend_unavailable"))
    c = LoginCache(reads, refresh=100, validity=200, retry=50, spacing=0.3)
    try:
        c.start()
        login = c.current()
        for expected in (2, 3):
            c.report_failure(login, forget=False)
            assert wait_until(lambda: reads.count >= expected)
        gaps = [b - a for a, b in zip(reads.times, reads.times[1:])]
        assert all(gap >= 0.29 for gap in gaps), gaps
    finally:
        assert c.stop()


class Boom(BaseException):
    """Défaut hors `Exception` : simule un bug qui tue la boucle."""


def test_boucle_morte_expire_puis_refus_ferme_sans_redemarrage(caplog):
    from mcp_vault.storage.pg_login import LoginCache
    clock = Clock()
    reads = Reads(login_value(), Boom())
    c = LoginCache(reads, refresh=0.05, validity=60, retry=0.02, spacing=0, clock=clock)
    with caplog.at_level(logging.ERROR, logger="mcp-vault.metadata-login"):
        c.start()
        assert wait_until(lambda: not c._thread.is_alive()), "la boucle aurait dû mourir"
    assert c.dead
    assert [r.getMessage() for r in caplog.records if "refresher_died" in r.getMessage()]
    assert c.current().value == login_value()
    # Aucun redémarrage, même réveillée.
    c.report_failure(c.current(), forget=False)
    time.sleep(0.2)
    assert reads.count == 2
    clock.now += 60
    with pytest.raises(MetadataUnavailable, match="login_refresher_dead"):
        c.current()
    assert c.stop()


def test_arret_termine_le_thread_et_oublie_le_login():
    from mcp_vault.storage.pg_login import LoginCache
    c = LoginCache(Reads(login_value()), refresh=100, validity=200)
    c.start()
    assert c.stop(timeout=2)
    assert not c._thread.is_alive()
    with pytest.raises(MetadataUnavailable):
        c.current()


# =============================================================================
# 3) Chemin réel : connection(), admit(), opérateur, cycle de vie
# =============================================================================

@pytest.fixture
def pg(monkeypatch):
    from mcp_vault.config import get_settings
    values = {"METADATA_BACKEND": "postgres", "METADATA_INSTANCE_ID": "test-vault",
              "METADATA_PG_VAULT_ID": "ssh-ca-prod", "METADATA_PG_SECRET_PATH": "app/connection",
              "METADATA_PG_PROVISIONER_SECRET_PATH": "provisioner/connection", "METADATA_PG_DATABASE": "vault",
              "METADATA_PG_OWNER_ROLE": "vault_owner", "METADATA_PG_APP_ROLE": "vault_app",
              "METADATA_PG_PROVISIONER_ROLE": "vault_provisioner", "METADATA_PG_CA_FILE": "unit-ca.crt",
              "ADMIN_BOOTSTRAP_KEY": "a" * 64}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


class Cursor:
    def __init__(self, rows):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeServer:
    """Répond aux contrôles de `connection()` et aux lectures de `load_facts`."""

    def __init__(self):
        self.connects = []
        self.role = None  # None = l'utilisateur qui s'est connecté
        self.refuse = False
        self.revoked = False
        self.revision = 1

    def connect(self, **kwargs):
        import psycopg
        self.connects.append(kwargs["password"])
        if self.refuse:
            raise psycopg.OperationalError("connection failed")
        return FakeConnection(self, kwargs["user"])


class FakeConnection:
    def __init__(self, server, user):
        self.server, self.user = server, user

    def close(self):
        pass

    def execute(self, query, params=None, **kwargs):
        q = " ".join(query.split())
        s = self.server
        if q.startswith("SELECT current_database() AS db"):
            return Cursor([{"db": "vault", "role": s.role or self.user}])
        if "set_config" in q or q in {"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "COMMIT", "ROLLBACK"}:
            return Cursor([{}])
        if "rolsuper, rolcreatedb" in q:
            return Cursor([dict.fromkeys(("rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication",
                                          "rolbypassrls"), False)])
        if "AS db," in q:
            return Cursor([{"db": False, "public": False, "temp": False}])
        if "pg_has_role" in q:
            return Cursor([{"owner": False, "provisioner": False}])
        if "AS member" in q:
            return Cursor([{"member": False}])
        if "schema_version" in q:
            return Cursor([{"version": 2}])
        if "AS ddl" in q:
            return Cursor([{"ddl": False}])
        if "bool_and(has_table_privilege" in q:
            return Cursor([{"allowed": True}])
        if "pg_get_userbyid(nspowner)" in q:
            return Cursor([{"owner": "vault_owner"}])
        if "pg_default_acl" in q or "FROM pg_namespace n" in q or "FROM pg_database d" in q:
            return Cursor([{"allowed": False}])
        if "FROM vault_metadata.tokens WHERE instance_id" in q:
            return Cursor([{"payload": {"hash": TOKEN_HASH, "client_name": "business", "permissions": ["read"],
                                        "allowed_resources": ["ordinary"], "policy_id": "", "revoked": s.revoked,
                                        "created_at": "2026-10-14T00:00:00+00:00",
                                        "expires_at": "2030-01-01T00:00:00+00:00"},
                            "revision": s.revision}])
        if "vault_metadata.mission_bindings" in q or "vault_metadata.policies" in q:
            return Cursor([])
        if q.startswith("SELECT 1 FROM vault_metadata.") or "FROM vault_metadata.operation_receipts r" in q:
            return Cursor([])
        raise AssertionError("requête non prévue : " + q[:80])


@pytest.fixture
def server(pg, monkeypatch):
    import psycopg
    from mcp_vault.storage import audit_schema, postgres
    fake = FakeServer()
    monkeypatch.setattr(psycopg, "connect", fake.connect)
    monkeypatch.setattr(audit_schema, "verify", lambda conn, settings: None)
    monkeypatch.setattr(postgres, "_slots", threading.BoundedSemaphore(4))
    fake.vault = {"app": [], "provisioner": []}

    def credentials(*, provisioner=False, login_refresh=False):
        kind = "provisioner" if provisioner else "app"
        fake.vault[kind].append(1)
        fake.vault.setdefault("login_refresh", []).append(login_refresh)
        outcome = fake.vault.get(kind + "_next")
        if isinstance(outcome, BaseException):
            raise outcome
        if provisioner:
            return login_value(PROVISIONER_PASSWORD, "vault_provisioner")
        return outcome or login_value()
    monkeypatch.setattr(postgres, "credentials", credentials)
    return fake


def open_app():
    from mcp_vault.storage.postgres import connection
    with connection() as conn:
        return conn


def test_requetes_lisent_la_memoire_et_les_faits_du_token_restent_frais(server):
    """Une seule lecture du coffre pour toutes les requêtes ; révocation visible tout de suite."""
    from mcp_vault.storage import admission, pg_login
    assert pg_login.start() is True
    first = asyncio.run(admission.admit(TOKEN))
    assert first["actor_revision"] == 1 and first["token"]._tokens[TOKEN_HASH]["revoked"] is False
    server.revoked, server.revision = True, 2
    second = asyncio.run(admission.admit(TOKEN))
    assert second["actor_revision"] == 2 and second["token"]._tokens[TOKEN_HASH]["revoked"] is True
    assert len(server.vault["app"]) == 1
    assert server.connects == [APP_PASSWORD, APP_PASSWORD]


def test_retour_arriere_reglages_a_zero_lit_le_coffre_a_chaque_connexion(server, monkeypatch):
    """Ancien contrat conservé quand l'exploitant met les deux réglages à 0."""
    from mcp_vault.config import get_settings
    from mcp_vault.storage import pg_login
    monkeypatch.setenv("METADATA_PG_LOGIN_REFRESH_SECONDS", "0")
    monkeypatch.setenv("METADATA_PG_LOGIN_VALIDITY_SECONDS", "0")
    get_settings.cache_clear()
    assert pg_login.start() is None and pg_login.active() is None
    for _ in range(3):
        open_app()
    assert len(server.vault["app"]) == 3 and len(server.connects) == 3


def test_hors_serveur_sans_demarrage_lecture_du_coffre_a_chaque_connexion(server):
    """Scripts et jobs ne démarrent pas la mémoire : comportement inchangé."""
    for _ in range(2):
        open_app()
    assert len(server.vault["app"]) == 2


def test_avant_premiere_lecture_reussie_aucune_connexion_pg(server):
    from mcp_vault.storage import pg_login
    server.vault["app_next"] = MetadataUnavailable("vault_unavailable")
    assert pg_login.start() is False
    with pytest.raises(MetadataUnavailable, match="login_unavailable"):
        open_app()
    assert server.connects == []


def test_pret_seulement_apres_une_lecture_reussie(server):
    from mcp_vault import lifecycle
    from mcp_vault.storage import pg_login
    server.vault["app_next"] = MetadataUnavailable("backend_unavailable")
    lifecycle._reset_shutdown_state()
    assert pg_login.start() is False
    assert asyncio.run(lifecycle._metadata_readiness()) is False
    server.vault["app_next"] = None
    pg_login.active().refresh_once()
    lifecycle._reset_shutdown_state()
    assert asyncio.run(lifecycle._metadata_readiness()) is True


def test_provisionneur_relit_toujours_le_coffre(server):
    from mcp_vault.storage import pg_login
    from mcp_vault.storage.postgres import connection
    pg_login.start()
    for _ in range(2):
        with connection(provisioner=True, schema=False):
            pass
    assert len(server.vault["provisioner"]) == 2
    assert server.connects == [PROVISIONER_PASSWORD, PROVISIONER_PASSWORD]


def test_chemin_operateur_relit_le_coffre_pour_le_login_app(server):
    from mcp_vault.storage import operator, pg_login
    pg_login.start()
    before = len(server.vault["app"])
    mutation = "c837848f-a3cb-4449-8be8-c9c9fdb8a3e5"
    for _ in range(2):
        operator.action("installation-result/" + mutation, {"token_hash": TOKEN_HASH, "client_name": "x"})
    assert len(server.vault["app"]) == before + 2
    # Hors opérateur, la mémoire sert de nouveau.
    open_app()
    assert len(server.vault["app"]) == before + 2


def test_identite_inattendue_via_connection_oublie_et_relit(server):
    from mcp_vault.storage import pg_login
    pg_login.start()
    server.role = "vault_owner"
    with pytest.raises(MetadataUnavailable, match="identity_invalid"):
        open_app()
    server.role = None
    # Relecture immédiate par la boucle, puis service rétabli.
    assert wait_until(lambda: len(server.vault["app"]) == 2)
    assert wait_until(lambda: pg_login.active()._login is not None)
    open_app()


def test_echec_de_connexion_relit_sans_retenter_la_requete(server):
    from mcp_vault.storage import pg_login
    pg_login.start()
    server.refuse = True
    with pytest.raises(MetadataUnavailable, match="connect_failed"):
        open_app()
    assert len(server.connects) == 1, "la requête en échec ne doit pas être retentée"
    assert wait_until(lambda: len(server.vault["app"]) == 2), "aucune relecture immédiate"


def test_demarrage_lit_le_login_apres_l_unseal(server, monkeypatch, tmp_path):
    from mcp_vault import lifecycle, s3_sync
    from mcp_vault.openbao import lifecycle as ob_lifecycle
    from mcp_vault.openbao import manager
    from mcp_vault.storage import pg_login
    order = []

    async def unseal():
        order.append("unseal")
        return {"status": "unsealed"}

    def start():
        order.append("login")
        return True
    monkeypatch.setattr(lifecycle, "_check_local_data_status", lambda data_dir: True)
    monkeypatch.setattr(lifecycle.get_settings(), "openbao_data_dir", str(tmp_path))
    monkeypatch.setattr(s3_sync, "reopen_periodic_sync", lambda: True)
    monkeypatch.setattr(s3_sync, "start_periodic_sync", AsyncMock())
    monkeypatch.setattr(manager, "start_openbao", AsyncMock(return_value=True))
    monkeypatch.setattr(ob_lifecycle, "initialize_vault", AsyncMock(return_value={"status": "already_initialized"}))
    monkeypatch.setattr(ob_lifecycle, "unseal_vault", unseal)
    monkeypatch.setattr(pg_login, "start", start)
    lifecycle._reset_shutdown_state()
    assert asyncio.run(lifecycle.vault_startup()) is True
    assert order == ["unseal", "login"]


def test_arret_de_l_application_arrete_la_relecture(server, monkeypatch):
    from unittest.mock import MagicMock, patch
    from mcp_vault import lifecycle
    from mcp_vault.storage import pg_login
    pg_login.start()
    thread = pg_login.active()._thread
    lifecycle._reset_shutdown_state()
    with patch.multiple("mcp_vault.s3_sync", stop_periodic_sync=AsyncMock(return_value=True),
                        upload_to_s3=AsyncMock(return_value=True)), \
            patch.multiple("mcp_vault.openbao.lifecycle", seal_vault=AsyncMock(return_value={"status": "sealed"}),
                           clear_in_memory_keys=MagicMock()), \
            patch.multiple("mcp_vault.openbao.manager", stop_openbao=AsyncMock()):
        asyncio.run(lifecycle.vault_shutdown(skip_upload=True))
    lifecycle._reset_shutdown_state()
    assert pg_login.active() is None and not thread.is_alive()


@pytest.mark.parametrize("refresh,validity", [(30, 60), (0, 0), (5, 6), (300, 900)])
def test_reglages_acceptes(pg, monkeypatch, refresh, validity):
    from mcp_vault.config import Settings
    monkeypatch.setenv("METADATA_PG_LOGIN_REFRESH_SECONDS", str(refresh))
    monkeypatch.setenv("METADATA_PG_LOGIN_VALIDITY_SECONDS", str(validity))
    s = Settings(_env_file=None)
    assert (s.metadata_pg_login_refresh_seconds, s.metadata_pg_login_validity_seconds) == (refresh, validity)


def test_reglages_par_defaut(pg):
    assert (pg.metadata_pg_login_refresh_seconds, pg.metadata_pg_login_validity_seconds) == (30, 60)


@pytest.mark.parametrize("refresh,validity", [(0, 60), (30, 0), (30, 30), (60, 30), (4, 60), (301, 900),
                                              (30, 901), (-1, 60)])
def test_reglages_refuses(pg, monkeypatch, refresh, validity):
    from pydantic import ValidationError
    from mcp_vault.config import Settings
    monkeypatch.setenv("METADATA_PG_LOGIN_REFRESH_SECONDS", str(refresh))
    monkeypatch.setenv("METADATA_PG_LOGIN_VALIDITY_SECONDS", str(validity))
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


# =============================================================================
# 4) Journal de la raison des 503 de admitted_call
# =============================================================================

def call(reason=None, inner=None):
    from mcp_vault.storage import admission
    sent = []

    async def send(message):
        sent.append(message)

    async def fn(scope, receive, send_):
        raise MetadataUnavailable(inner)
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer " + TOKEN.encode())]}

    async def run():
        if reason is not None:
            original = admission.admit
            admission.admit = AsyncMock(side_effect=MetadataUnavailable(reason))
            try:
                await admission.admitted_call(scope, None, send, fn)
            finally:
                admission.admit = original
        else:
            await admission.admitted_call(scope, None, send, fn)
    asyncio.run(run())
    return sent[0]["status"]


def records(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "mcp-vault.metadata"]


def test_503_d_admission_journalise_la_raison_fermee(pg, caplog):
    with caplog.at_level(logging.WARNING, logger="mcp-vault.metadata"):
        assert call(reason="login_expired") == 503
    (line,) = records(caplog)
    assert "raison=login_expired" in line
    assert TOKEN not in line and APP_PASSWORD not in line


def test_503_pendant_l_appel_journalise_la_raison(pg, monkeypatch, caplog):
    from mcp_vault.storage import admission
    monkeypatch.setattr(admission, "admit", AsyncMock(return_value={"owners": {}}))
    with caplog.at_level(logging.WARNING, logger="mcp-vault.metadata"):
        assert call(inner="connect_failed") == 503
    assert ["raison=connect_failed" in line for line in records(caplog)] == [True]


def test_rafale_de_503_limitee_a_une_ligne_par_raison(pg, monkeypatch, caplog):
    from mcp_vault.storage import admission
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(admission.time, "monotonic", lambda: clock.now)
    with caplog.at_level(logging.WARNING, logger="mcp-vault.metadata"):
        for _ in range(50):
            call(reason="admission_timeout")
        call(reason="login_unavailable")
        clock.now += admission.UNAVAILABLE_LOG_INTERVAL_SECONDS
        call(reason="admission_timeout")
    lines = records(caplog)
    assert len(lines) == 3
    assert "lignes supprimées=49" in lines[2]


def test_raison_hors_format_journalisee_comme_non_classee(pg, caplog):
    with caplog.at_level(logging.WARNING, logger="mcp-vault.metadata"):
        call(reason="postgresql://user:secret@host/db")
    (line,) = records(caplog)
    assert "raison=unclassified" in line and "secret" not in line


# =============================================================================
# 5) Constats de revue : refus HTTP au corps illisible, réveil tardif, arrêt
# =============================================================================

@pytest.mark.parametrize("status,body", [(401, b"<html>denied</html>"), (403, b""), (403, b"not json")])
def test_refus_http_au_corps_illisible_oublie_le_login(pg, monkeypatch, status, body):
    """Parcours réel credentials() puis reader : le statut décide, pas le corps."""
    import httpx
    from mcp_vault.openbao import manager
    from mcp_vault.storage import pg_login
    import json as _json
    monkeypatch.setattr(manager, "get_hvac_client", lambda: SimpleNamespace(token="unit-token"))
    responses = [httpx.Response(200, content=_json.dumps({"data": {"data": login_value()}}).encode()),
                 httpx.Response(status, content=body)]
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda request: responses.pop(0)), **kwargs))
    assert pg_login.start() is True
    memory = pg_login.active()
    assert memory.current().value == login_value()
    memory.refresh_once()
    assert memory.last_error == "backend_denied"
    with pytest.raises(MetadataUnavailable, match="login_refused"):
        memory.current()


class PausingLock:
    """Verrou qui suspend un thread désigné juste APRÈS sa prochaine libération."""

    def __init__(self, log):
        self.real = threading.Lock()
        self.log = log
        self.target = None
        self.paused = threading.Event()
        self.resume = threading.Event()

    def __enter__(self):
        self.real.acquire()
        return self

    def __exit__(self, *exc):
        self.real.release()
        if threading.current_thread() is self.target:
            self.target = None
            self.paused.set()
            self.resume.wait(5)
            self.log.append(("resumed", threading.current_thread().name))


class RecordingEvent(threading.Event):
    """Événement de réveil qui note quel thread le pose, dans l'ordre."""

    def __init__(self, log):
        super().__init__()
        self.log = log

    def set(self):
        self.log.append(("set", threading.current_thread().name))
        super().set()


def test_refus_tardif_du_meme_login_ne_relance_pas_de_lecture():
    """Entrelacement imposé : A vérifie le login, est suspendu juste après avoir
    rendu le verrou, B déclenche la relecture qui installe un nouveau login,
    puis A reprend. A ne doit poser aucun réveil après sa reprise."""
    from mcp_vault.storage.pg_login import LoginCache
    log = []
    reads = Reads(login_value("old"), login_value("new"), login_value("third"))
    c = LoginCache(reads, refresh=100, validity=200, retry=50, spacing=0)
    lock = PausingLock(log)
    c._lock = lock
    c._wake = RecordingEvent(log)
    try:
        c.start()
        old = c.current()
        a = threading.Thread(target=lambda: c.report_failure(old, forget=False), name="worker-a")
        lock.target = a
        a.start()
        assert lock.paused.wait(2)
        c.report_failure(old, forget=False)  # B
        assert wait_until(lambda: c.current().value["password"] == "new")
        lock.resume.set()
        a.join(2)
        assert not a.is_alive()
        resumed = log.index(("resumed", "worker-a"))
        assert ("set", "worker-a") not in log[resumed:], log
        assert not c._wake.is_set()
        assert reads.count == 2
    finally:
        lock.resume.set()
        assert c.stop()


def test_lecture_terminee_apres_l_arret_ne_republie_pas_le_login():
    from mcp_vault.storage.pg_login import LoginCache
    entered, release = threading.Event(), threading.Event()
    calls = []

    def read():
        calls.append(1)
        if len(calls) == 2:
            entered.set()
            release.wait(5)
        return login_value(f"p{len(calls)}")
    c = LoginCache(read, refresh=100, validity=200, retry=50, spacing=0)
    c.start()
    c.report_failure(c.current(), forget=False)
    assert entered.wait(2)
    assert c.stop(timeout=0.1) is False, "le thread est encore dans sa lecture"
    release.set()
    assert wait_until(lambda: not c._thread.is_alive())
    # Avant tout second arrêt, qui oublierait de nouveau et masquerait le défaut.
    with pytest.raises(MetadataUnavailable):
        c.current()
    assert c.stop(timeout=2) is True


def test_singleton_garde_et_draine_une_memoire_encore_en_lecture(server, monkeypatch):
    from mcp_vault.storage import pg_login
    entered, release = threading.Event(), threading.Event()
    assert pg_login.start() is True
    memory = pg_login.active()

    def blocked():
        entered.set()
        release.wait(5)
        return login_value("late")
    memory._read = blocked
    memory.report_failure(memory.current(), forget=False)
    assert entered.wait(2)
    monkeypatch.setattr(memory, "stop", lambda timeout=10.0, real=memory.stop: real(timeout=0.1))
    assert pg_login.stop() is False
    assert pg_login.active() is None and pg_login._draining == [memory]
    release.set()
    assert wait_until(lambda: not memory._thread.is_alive())
    assert pg_login.stop() is True and pg_login._draining == []
    with pytest.raises(MetadataUnavailable):
        memory.current()


def test_arret_pendant_la_lecture_initiale_attend_et_ne_cree_aucun_thread():
    from mcp_vault.storage.pg_login import LoginCache
    entered, release = threading.Event(), threading.Event()

    def read():
        entered.set()
        release.wait(5)
        return login_value()
    c = LoginCache(read, refresh=100, validity=200)
    result = {}
    starter = threading.Thread(target=lambda: result.setdefault("start", c.start()))
    starter.start()
    assert entered.wait(2)
    assert c.stop(timeout=0.1) is False, "lecture initiale en vol : pas encore drainée"
    release.set()
    starter.join(2)
    assert result["start"] is False and c._thread is None
    assert c.stop(timeout=2) is True
    with pytest.raises(MetadataUnavailable):
        c.current()


def test_arret_du_module_draine_la_lecture_initiale(server):
    from mcp_vault.storage import pg_login
    from mcp_vault.storage import postgres
    entered, release = threading.Event(), threading.Event()
    real = postgres.credentials

    def blocked(**kwargs):
        entered.set()
        release.wait(5)
        return real(**kwargs)
    postgres.credentials = blocked
    try:
        starter = threading.Thread(target=pg_login.start)
        starter.start()
        assert entered.wait(2)
        memory = pg_login.active()
        result = {}
        stopper = threading.Thread(target=lambda: result.setdefault("stop", pg_login.stop()))
        stopper.start()
        stopper.join(0.3)
        assert stopper.is_alive(), "stop() a conclu alors que la lecture initiale est en vol"
        release.set()
        stopper.join(5)
        starter.join(5)
    finally:
        release.set()
        postgres.credentials = real
    assert result["stop"] is True and pg_login._draining == []
    assert pg_login.active() is None and memory._thread is None


def test_deux_demarrages_concurrents_ne_laissent_aucun_thread_orphelin(server, monkeypatch):
    """A est suspendu entre l'arrêt de l'ancienne mémoire et l'installation de la
    sienne ; B démarre pendant ce temps. Aucune mémoire ne doit échapper à stop()."""
    from mcp_vault.storage import pg_login
    created, paused, resume = [], threading.Event(), threading.Event()
    real = pg_login.LoginCache

    class Tracked(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)
            if threading.current_thread().name == "start-a":
                paused.set()
                resume.wait(5)
    class ObservedLock:
        """Verrou de cycle de vie qui signale la TENTATIVE d'acquisition par B."""

        def __init__(self, real_lock):
            self.real_lock = real_lock
            self.b_attempted = threading.Event()

        def __enter__(self):
            if threading.current_thread().name == "start-b":
                self.b_attempted.set()
            self.real_lock.acquire()
            return self

        def __exit__(self, *exc):
            self.real_lock.release()
    lock = ObservedLock(pg_login._lifecycle_lock)
    monkeypatch.setattr(pg_login, "LoginCache", Tracked)
    monkeypatch.setattr(pg_login, "_lifecycle_lock", lock)
    a = threading.Thread(target=pg_login.start, name="start-a")
    b = threading.Thread(target=pg_login.start, name="start-b")
    a.start()
    assert paused.wait(2)
    b.start()
    # B a réellement tenté le démarrage : soit il attend le verrou, soit (code
    # sans verrou) il a déjà terminé. Ce n'est qu'ensuite que A reprend.
    assert wait_until(lambda: lock.b_attempted.is_set() or not b.is_alive())
    resume.set()
    a.join(5)
    b.join(5)
    assert len(created) == 2
    assert pg_login.stop() is True
    assert all(m._thread is None or not m._thread.is_alive() for m in created), "thread orphelin"
    assert pg_login._draining == [] and pg_login.active() is None


def test_aucune_lecture_initiale_apres_un_arret_deja_conclu():
    """start() repris après un stop() qui a conclu : aucune lecture du coffre,
    aucun thread, et le drainage reste vrai."""
    from mcp_vault.storage.pg_login import LoginCache
    reads = Reads(login_value())
    c = LoginCache(reads, refresh=100, validity=200)
    assert c.stop(timeout=1) is True
    assert c.start() is False
    assert reads.count == 0 and c._thread is None
    assert c.stop(timeout=1) is True


# =============================================================================
# 6) Place dédiée du lecteur KV pour la relecture du login
# =============================================================================

class BlockedOpenBao:
    """Faux OpenBao derrière le vrai lecteur : les lectures propriétaire
    restent bloquées dans la réponse HTTP, donc gardent leur place du lecteur."""

    def __init__(self, monkeypatch):
        import httpx
        import json as _json
        from mcp_vault.openbao import manager
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.owner_in_flight = 0
        self.login_in_flight = 0
        self.login_entered = threading.Event()
        self.login_release = threading.Event()
        self.login_release.set()
        monkeypatch.setattr(manager, "get_hvac_client", lambda: SimpleNamespace(token="unit-token"))
        login = _json.dumps({"data": {"data": login_value()}}).encode()
        owner = _json.dumps({"data": {"data": {"created_by": "business"}}}).encode()

        def handle(request):
            if request.url.path.endswith("/_vault_meta"):
                with self.lock:
                    self.owner_in_flight += 1
                self.release.wait(5)
                return httpx.Response(200, content=owner)
            self.login_entered.set()
            self.login_release.wait(5)
            return httpx.Response(200, content=login)

        real_client = httpx.Client
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
            transport=httpx.MockTransport(handle), **kwargs))

    def saturate(self, n=4):
        """N lectures propriétaire réelles, bloquées en vol : le lecteur est plein."""
        from mcp_vault.storage import reader
        threads = [threading.Thread(target=reader.owner_metadata, args=("ordinary",)) for _ in range(n)]
        for t in threads:
            t.start()
        assert wait_until(lambda: self.owner_in_flight == n)
        self.threads = threads

    def drain(self):
        self.release.set()
        self.login_release.set()
        for t in self.threads:
            t.join(5)
        assert not any(t.is_alive() for t in self.threads)


def test_relecture_du_login_passe_quand_les_lectures_proprietaire_saturent_le_lecteur(pg, monkeypatch):
    """Les 4 places du lecteur prises par des lectures propriétaire : la lecture
    initiale et la relecture de fond du login réussissent quand même, alors
    qu'une 5e lecture propriétaire est bien refusée. Sans place dédiée, le login
    expirerait et toutes les requêtes tomberaient en login_expired."""
    from mcp_vault.storage import pg_login, reader
    bao = BlockedOpenBao(monkeypatch)
    bao.saturate(4)
    try:
        assert pg_login.start() is True
        memory = pg_login.active()
        memory.refresh_once()
        assert memory.last_error == ""
        assert memory.current().value == login_value()
        # La saturation est réelle, et la lecture du login n'a pas pris (ni
        # rendu) une place du lecteur commun.
        with pytest.raises(MetadataUnavailable, match="reader_admission_timeout"):
            reader.owner_metadata("ordinary")
    finally:
        bao.drain()


def test_les_autres_lectures_du_login_restent_sur_le_lecteur_commun(pg, monkeypatch):
    """Retour arrière (lecture à chaque connexion), provisionneur et opérateur
    gardent le lecteur commun : saturé, il les refuse comme avant."""
    from mcp_vault.storage import postgres
    bao = BlockedOpenBao(monkeypatch)
    bao.saturate(4)
    try:
        for provisioner in (False, True):
            with pytest.raises(MetadataUnavailable, match="reader_admission_timeout"):
                postgres.credentials(provisioner=provisioner)
    finally:
        bao.drain()


def test_la_place_du_login_est_unique(pg, monkeypatch):
    """Une seule lecture du login à la fois sur la place dédiée : une seconde,
    concurrente, attend puis reçoit reader_admission_timeout."""
    from mcp_vault.storage import postgres
    bao = BlockedOpenBao(monkeypatch)
    bao.threads = []
    bao.login_release.clear()
    first = threading.Thread(target=postgres.credentials, kwargs={"login_refresh": True})
    first.start()
    try:
        assert bao.login_entered.wait(2)
        with pytest.raises(MetadataUnavailable, match="reader_admission_timeout"):
            postgres.credentials(login_refresh=True)
    finally:
        bao.drain()
        first.join(5)
    assert not first.is_alive()
