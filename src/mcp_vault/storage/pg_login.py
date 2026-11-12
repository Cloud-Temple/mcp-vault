"""Login PostgreSQL applicatif des métadonnées, gardé en mémoire et relu en fond.

Seul le login de la base (`METADATA_PG_SECRET_PATH`) est gardé. Les tokens,
policies, bindings et droits restent relus dans PostgreSQL à chaque requête
(`admission.load_facts`, `postgres.revalidate_actor`) : une révocation reste
immédiate. Le login vit en mémoire seulement et n'est jamais journalisé.

Modèle :

- le serveur lit le login juste après l'unseal ; `/ready` reste rouge tant
  qu'aucun login valide n'est en mémoire, car la sonde passe par `connection()` ;
- un thread relit le coffre toutes les `METADATA_PG_LOGIN_REFRESH_SECONDS`
  (30 s par défaut). Les requêtes lisent la mémoire, jamais le coffre ;
- le login reste valable `METADATA_PG_LOGIN_VALIDITY_SECONDS` (60 s par défaut)
  après le DÉBUT de la dernière lecture réussie. Au-delà, refus fermé ;
- après un échec de lecture, nouvel essai toutes les 5 s. Un échec ne
  prolonge jamais la validité. Un refus explicite du coffre (401/403, absence
  confirmée, contenu invalide) fait oublier le login tout de suite ;
- un échec de connexion PG réveille la boucle pour une relecture immédiate.
  Une identité SQL inattendue fait en plus oublier le login fautif. Un login
  plus récent n'est jamais effacé, et la requête en échec n'est pas retentée ;
- les deux réglages à 0 rétablissent la lecture du coffre à chaque connexion.

Hors du serveur (scripts, jobs en ligne de commande), personne ne démarre ce
module : `connection()` relit alors le coffre à chaque fois, comme avant.
Les chemins opérateur et provisionneur relisent aussi le coffre à chaque fois.
"""

import logging
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar

from ..config import get_settings
from .postgres import MetadataUnavailable

logger = logging.getLogger("mcp-vault.metadata-login")

# Délai de réessai après un échec de lecture. Le mandat fixe deux réglages
# seulement (relecture, validité) ; celui-ci reste une constante.
RETRY_SECONDS = 5.0
# Écart minimal entre deux lectures déclenchées par des échecs PG en rafale.
TRIGGER_SPACING_SECONDS = 1.0
# Réponses du coffre qui disent que le login actuel n'est plus le bon.
EXPLICIT_REFUSALS = frozenset({"backend_denied", "metadata_absent_confirmed", "connection_invalid"})

_fresh_reads = ContextVar("vault_pg_fresh_login", default=False)


class Login:
    """Un login lu dans le coffre, lié à sa génération. `repr` sans secret."""

    __slots__ = ("value", "generation")

    def __init__(self, value, generation):
        self.value = value
        self.generation = generation

    def __repr__(self):
        return f"Login(generation={self.generation})"


class LoginCache:
    """État du login en mémoire. L'horloge et la lecture sont injectables."""

    def __init__(self, read, *, refresh, validity, retry=RETRY_SECONDS,
                 spacing=TRIGGER_SPACING_SECONDS, clock=time.monotonic):
        if not 0 < refresh < validity:
            raise ValueError("refresh < validity requis")
        self._read = read
        self._refresh = float(refresh)
        self._validity = float(validity)
        self._retry = float(min(retry, refresh))
        self._spacing = float(spacing)
        self._clock = clock
        self._lock = threading.Lock()
        # Une seule lecture du coffre à la fois, quel que soit l'appelant.
        self._read_lock = threading.Lock()
        self._dead = False
        self._login = None
        self._valid_until = 0.0
        self._generation = 0
        self._absent = "login_unavailable"
        self._last_read = None
        self._last_error = ""
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None

    # ── Lecture par les requêtes ──────────────────────────────────────

    def current(self):
        """Le login à utiliser, ou un refus fermé. Ne lit jamais le coffre."""
        with self._lock:
            if self._login is not None and self._clock() >= self._valid_until:
                self._forget("login_refresher_dead" if self._dead else "login_expired")
            if self._login is None:
                raise MetadataUnavailable(self._absent)
            return self._login

    def report_failure(self, login, *, forget):
        """Un échec PG avec `login`. Sans effet si un login plus récent est en place."""
        with self._lock:
            if self._login is not login:
                return False
            if forget:
                self._forget("login_refused")
        self._wake.set()
        return True

    # ── Relecture ─────────────────────────────────────────────────────

    def refresh_once(self):
        """Une lecture du coffre. Rend le délai avant la lecture suivante."""
        with self._read_lock:
            return self._refresh_locked()

    def _refresh_locked(self):
        started = self._clock()
        with self._lock:
            self._last_read = started
        try:
            value = self._read()
        except MetadataUnavailable as exc:
            return self._failed(exc.reason)
        except Exception:  # noqa: BLE001, une lecture ratée ne tue jamais la boucle
            return self._failed("login_read_failed")
        with self._lock:
            self._generation += 1
            self._login = Login(value, self._generation)
            self._valid_until = started + self._validity
            # Les réveils en attente visaient un login désormais remplacé :
            # N refus du même login donnent au plus une lecture. Un arrêt
            # posé sous ce même verrou n'est jamais effacé.
            if not self._stop.is_set():
                self._wake.clear()
            recovered = self._last_error
            self._last_error = ""
        if recovered:
            logger.info("Login PG des métadonnées relu après échec (%s)", recovered)
        return self._refresh

    def _failed(self, reason):
        with self._lock:
            changed = reason != self._last_error
            self._last_error = reason
            refused = reason in EXPLICIT_REFUSALS and self._login is not None
            if reason in EXPLICIT_REFUSALS:
                self._forget("login_refused")
        if changed or refused:
            logger.warning("Lecture du login PG des métadonnées en échec (%s)%s", reason,
                           " : login oublié" if refused else "")
        return self._retry

    def _forget(self, reason):
        self._login = None
        self._valid_until = 0.0
        self._absent = reason

    # ── Boucle de fond ────────────────────────────────────────────────

    def start(self):
        """Lecture initiale synchrone, puis boucle de fond. Rend True si un login est en mémoire."""
        delay = self.refresh_once()
        self._thread = threading.Thread(target=self._run, args=(delay,),
                                        name="metadata-pg-login", daemon=True)
        self._thread.start()
        with self._lock:
            return self._login is not None

    def _run(self, delay):
        try:
            self._loop(delay)
        except BaseException:  # noqa: BLE001, journalisée, jamais relancée
            # Pas de redémarrage : le login en mémoire expire à sa validité,
            # puis les requêtes sont refusées avec `login_refresher_dead`.
            with self._lock:
                self._dead = True
            logger.error("Relecture de fond du login PG des métadonnées arrêtée (raison=refresher_died) : "
                         "refus fermé à l'expiration du login en mémoire")

    def _loop(self, delay):
        while True:
            woke = self._wake.wait(delay)
            if self._stop.is_set():
                return
            if woke:
                with self._lock:
                    if self._stop.is_set():
                        return
                    self._wake.clear()
                    last = self._last_read
                gap = 0 if last is None else last + self._spacing - self._clock()
                if gap > 0 and self._stop.wait(gap):
                    return
            delay = self.refresh_once()

    def stop(self, timeout=10.0):
        """Arrête la boucle et oublie le login. Rend True si le thread est terminé."""
        with self._lock:
            self._stop.set()
            self._wake.set()
        joined = True
        if self._thread is not None:
            self._thread.join(timeout)
            joined = not self._thread.is_alive()
        with self._lock:
            self._forget("login_unavailable")
        return joined

    @property
    def last_error(self):
        return self._last_error

    @property
    def dead(self):
        return self._dead


_active = None
_active_lock = threading.Lock()


def start():
    """Démarre la mémoire du login pour le serveur.

    Rend None si le profil ne l'utilise pas (S3, ou réglages à 0), sinon True
    ou False selon que la lecture initiale a réussi. Après un échec, la mémoire
    reste installée : les requêtes sont refusées jusqu'à une lecture réussie,
    au lieu de retomber silencieusement sur une lecture par connexion.
    """
    global _active
    s = get_settings()
    if s.metadata_backend != "postgres" or s.metadata_pg_login_refresh_seconds == 0:
        stop()
        return None
    from . import postgres
    cache = LoginCache(lambda: postgres.credentials(), refresh=s.metadata_pg_login_refresh_seconds,
                       validity=s.metadata_pg_login_validity_seconds)
    with _active_lock:
        previous, _active = _active, cache
    if previous is not None:
        previous.stop()
    return cache.start()


def stop():
    """Arrête la boucle et oublie le login. Rend True si rien ne reste en vol."""
    global _active
    with _active_lock:
        cache, _active = _active, None
    return True if cache is None else cache.stop()


def active():
    """La mémoire à utiliser pour une connexion app, ou None pour lire le coffre."""
    if _fresh_reads.get():
        return None
    return _active


@contextmanager
def fresh_reads():
    """Force la lecture du coffre à chaque connexion dans ce contexte (chemins opérateur)."""
    token = _fresh_reads.set(True)
    try:
        yield
    finally:
        _fresh_reads.reset(token)
