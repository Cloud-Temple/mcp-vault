"""Auth native d'abord ; aucune autorité SQL directe ou fallback."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from standalone_pg_files import endpoint, private_read, s3_ca_bundle


def native_token(config):
    auth = config["auth"]
    if auth["mode"] == "token_file":
        if "s3_ca_file" in auth:
            raise ValueError("CA S3 sans objet en mode token_file")
        token = private_read(auth["token_file"]).decode().strip()
    else:
        scripts = Path(__file__).resolve().parent
        environment = {
            "PATH": os.defpath,
            "PYTHONPATH": str(scripts.parent / "src"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if "s3_ca_file" in auth:
            # Seule variable relayée, validée AVANT tout lancement. Rien d'autre
            # de l'environnement du serveur (proxy, credentials, SSL_*) ne passe.
            environment["AWS_CA_BUNDLE"] = s3_ca_bundle(auth["s3_ca_file"])
        process = subprocess.run(
            [
                sys.executable,
                str(scripts / "standalone_pg_bootstrap.py"),
                config["settings_file"],
            ],
            cwd=Path(config["settings_file"]).parent,
            env=environment,
            capture_output=True,
            timeout=30,
            check=True,
        )
        token = process.stdout.decode().strip()
        del process
    if not token or len(token) > 16384 or "\n" in token:
        raise ValueError("Auth native indisponible")
    return token


class Native:
    def __init__(self, config):
        self.config = config
        self.token = native_token(config)
        self.request("GET", "auth/token/lookup-self")  # AVANT KV/SQL/probe.

    def close(self):
        self.token = ""

    def request(self, method, suffix, body=None, *, absent=False):
        url = endpoint(self.config["vault_url"], bao=True)
        # CA sans effet sur HTTP loopback. Aucune promesse TLS native.
        with httpx.Client(  # noqa: SIM117 - response closes before client
            verify=True,
            timeout=httpx.Timeout(5, connect=1),
            follow_redirects=False,
        ) as http:
            with http.stream(
                method,
                url + "/v1/" + suffix,
                headers={"X-Vault-Token": self.token},
                json=body,
            ) as response:
                chunks, deadline = bytearray(), time.monotonic() + 5
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > 65536 or time.monotonic() >= deadline:
                        raise ValueError("Réponse native hors borne")
                value = json.loads(chunks) if chunks else None
                if absent and response.status_code == 404 and value == {"errors": []}:
                    return None
                if response.status_code not in {200, 204}:
                    raise ValueError("Auth/lecture native non confirmée")
                return value

    def read(self, path):
        value = self.request(
            "GET",
            quote(self.config["mount"], safe="") + "/data/" + quote(path, safe="/"),
        )
        return value["data"]["data"]

    def put_new(self, path, value):
        suffix = quote(self.config["mount"], safe="") + "/data/" + quote(path, safe="/")
        existing = self.request("GET", suffix, absent=True)
        if existing is not None:
            if existing["data"]["data"] != value:
                raise ValueError("Credential déjà présent différent")
            return
        self.request("POST", suffix, {"options": {"cas": 0}, "data": value})
        if self.read(path) != value:
            raise ValueError("Écriture native non confirmée")
