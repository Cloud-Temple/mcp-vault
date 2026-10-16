"""Finite fixture support, imported only by the explicitly invoked PG/Bao recipe.

No production endpoint. Init material deliberately has no serialization path.
"""

from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import threading
from urllib.parse import urlsplit

import requests


def save(path, value):
    path = Path(path)
    raw = (
        value
        if isinstance(value, bytes)
        else (json.dumps(value, sort_keys=True, default=str, indent=2) + "\n").encode()
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    """Exclusive receipts BEFORE caller assertions; never serializes call arguments."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)

    def before(self, label):
        save(self.directory / (label + ".intent.json"), {"step": label, "retry": False})

    def received(self, label, value):
        save(self.directory / (label + ".received.private.json"), value)
        return value

    def call(self, label, fn):
        self.before(label)
        try:
            value = fn()
        except BaseException as exc:
            self.received(label, {"exception_type": type(exc).__name__})
            raise
        return self.received(label, value)

    async def acall(self, label, fn):
        self.before(label)
        try:
            value = await fn()
        except BaseException as exc:
            self.received(label, {"exception_type": type(exc).__name__})
            raise
        return self.received(label, value)


def loopback_url(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("fresh loopback Bao URL required")
    return url.rstrip("/")


def bootstrap_owner(url, client_factory):
    """The caller IS the owner process. No root or unseal key leaves its memory."""
    client = client_factory(url=loopback_url(url), timeout=(1, 2))
    if client.sys.is_initialized():
        raise ValueError("preexisting Bao refused")
    initialized = client.sys.initialize(secret_shares=1, secret_threshold=1)
    # Intentionally no Journal/init dump, print, env, file, child or return tuple.
    client.sys.submit_unseal_key(initialized["keys"][0])
    client.token = initialized["root_token"]
    del initialized
    if client.sys.is_sealed():
        raise ValueError("unseal not confirmed")
    return client


def read_policy(mount, path):
    # Closed fixture names; disallow HCL injection and wildcard grants.
    import re

    if not re.fullmatch(r"[a-z][a-z0-9-]{1,50}", mount):
        raise ValueError("mount")
    if not re.fullmatch(r"sql/[a-z-]{1,30}", path):
        raise ValueError("path")
    return 'path "' + mount + "/data/" + path + '" { capabilities = ["read"] }'


@contextmanager
def bao_http_receipts(url, journal):
    """Observe real hvac sends AFTER bootstrap, only this fixture's authority.

    No request header/body serialization. The owner init response is outside
    this context, so neither root nor unseal shares enter the journal.
    """
    origin = loopback_url(url)
    original = requests.Session.send
    events = []
    lock = threading.Lock()

    def send(session, request, **kwargs):
        parsed = urlsplit(request.url)
        if parsed.scheme + "://" + parsed.netloc != origin:
            return original(session, request, **kwargs)
        if parsed.query or request.url.startswith(origin + "/v1/sys/init"):
            raise ValueError("unexpected init/query in post-bootstrap observer")
        with lock:
            if len(events) >= 256:
                raise ValueError("finite HTTP observation bound")
            index = len(events)
            event = {
                "method": request.method,
                "path": parsed.path,
                "wrapped_request": bool(request.headers.get("X-Vault-Wrap-TTL")),
            }
            events.append(event)
        label = "http-" + str(index).zfill(3)
        journal.before(label)
        try:
            response = original(session, request, **kwargs)
        except BaseException as exc:
            journal.received(label, {**event, "exception_type": type(exc).__name__})
            raise
        if len(response.content) > 65536:
            journal.received(
                label, {**event, "status": response.status_code, "oversize": True}
            )
            raise ValueError("fixture response too large")
        event["status"] = response.status_code
        journal.received(label, {**event, "body": response.content.decode("utf-8")})
        return response

    requests.Session.send = send
    try:
        yield events
    finally:
        requests.Session.send = original


@contextmanager
def drop_unwrap_once(backend, token, journal):
    """One exact wrap credential, ONE real forward, then lose its real reply.

    No root, arbitrary forwarding, logging of headers, retries or proxy env.
    The fixture redirects only wrapping._get_config, not the PG/Vault reader.
    """
    backend = loopback_url(backend)
    lock = threading.Lock()
    state = {"forwards": 0, "status": None, "error": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if (
                self.path != "/v1/sys/wrapping/unwrap"
                or self.headers.get("X-Vault-Token") != token
                or self.headers.get("Transfer-Encoding")
                or int(self.headers.get("Content-Length", "0")) > 64
            ):
                self.send_error(403)
                return
            with lock:
                if state["forwards"]:
                    self.send_error(409)
                    return
                state["forwards"] = 1  # consumed BEFORE dispatch, including UNKNOWN
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                journal.before("unwrap-forward")
                with requests.Session() as session:
                    session.trust_env = False
                    response = session.post(
                        backend + self.path,
                        data=body,
                        headers={
                            "X-Vault-Token": token,
                            "Content-Type": "application/json",
                        },
                        timeout=(1, 2),
                        allow_redirects=False,
                    )
                journal.received(
                    "unwrap-forward",
                    {
                        "status": response.status_code,
                        "body": response.content.decode("utf-8"),
                        "sha256": hashlib.sha256(response.content).hexdigest(),
                    },
                )
                state["status"] = response.status_code
            except BaseException as exc:
                state["error"] = type(exc).__name__
            finally:
                # Do NOT return the ACK. Native hvac sees a real connection loss.
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()

        def do_GET(self):
            self.send_error(403)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        if thread.is_alive():
            raise RuntimeError("relay not drained")
