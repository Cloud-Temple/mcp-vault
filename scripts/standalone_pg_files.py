"""Fichiers privés et configuration fermée du seul domaine standalone."""

import hashlib
import json
import os
import ssl
import stat
from pathlib import Path
from urllib.parse import urlsplit

from standalone_pg_sql import identifier


def private_directory(path):
    info = Path(path).lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.geteuid()
    ):
        raise ValueError("Répertoire privé 0700 du propriétaire courant requis")


def private_read(path):
    private_directory(Path(path).parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
            or info.st_size > 65536
        ):
            raise ValueError(
                "Fichier privé régulier, propriétaire courant, <=64KiB requis"
            )
        return stream.read()


def private_write(path, content):
    private_directory(Path(path).parent)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact(value, fields, optional=""):
    if not isinstance(value, dict):
        raise ValueError("Champs manquants ou inconnus")
    required = set(fields.split())
    if not required <= set(value) <= required | set(optional.split()):
        raise ValueError("Champs manquants ou inconnus")


def s3_ca_bundle(path):
    """CA S3 explicite : mêmes invariants que private_read, PEM réellement chargeable.

    Le chemin n'est pas un secret ; il est relayé tel quel en AWS_CA_BUNDLE.
    """
    if type(path) is not str or not Path(path).is_absolute() or "\0" in path:
        raise ValueError("Chemin absolu de CA S3 requis")
    try:
        context = ssl.create_default_context(cadata=private_read(path).decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError):
        raise ValueError("CA S3 : bundle PEM illisible") from None
    if not context.cert_store_stats()["x509_ca"]:
        raise ValueError("CA S3 : aucun certificat d'autorité dans le bundle")
    return path


def endpoint(value, *, bao=False):
    parsed = urlsplit(value)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not parsed.hostname
    ):
        raise ValueError("Endpoint non canonique")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ValueError("HTTP limité au loopback")
    if bao and parsed.scheme != "http":
        raise ValueError("Bao embarqué attendu en HTTP loopback, sans listener public")
    return value.rstrip("/")


def load_config(path):
    config = json.loads(private_read(path))
    exact(
        config,
        "context execution topology instance mount roles domains infra_path settings_file compose_env_file carrier_dir vault_url vault_ca_file auth product_url product_ca_file pg_ca_file bootstrap_file initial_admin_file client_name tls",
    )
    if config["context"] not in {"source_fresh", "copy", "return"}:
        raise ValueError("Contexte explicite requis")
    if config["execution"] not in {"compose", "python"} or config["topology"] not in {
        "local",
        "external",
    }:
        raise ValueError("Variante inconnue")
    for name in ("instance", "mount", "client_name"):
        identifier(config[name])
    exact(config["roles"], "owner app provisioner maintenance backup restore")
    for role in config["roles"].values():
        identifier(role)
    if len(set(config["roles"].values())) != 6:
        raise ValueError("Six identités distinctes requises")
    exact(config["domains"], "source_fresh copy return")
    databases, paths = [], [config["infra_path"]]
    for domain in config["domains"].values():
        exact(domain, "database paths")
        identifier(domain["database"])
        databases.append(domain["database"])
        exact(domain["paths"], "app provisioner maintenance backup restore")
        paths += list(domain["paths"].values())
    import re

    if len(set(databases)) != 3 or len(set(paths)) != len(paths):
        raise ValueError("Bases et chemins distincts, sans écrasement")
    if any(
        not isinstance(p, str)
        or len(p) > 256
        or p.startswith("_vault_meta")
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*", p
        )
        for p in paths
    ):
        raise ValueError("Chemin KV non canonique")
    endpoint(config["vault_url"], bao=True)
    endpoint(config["product_url"])
    exact(config["auth"], "mode token_file", optional="s3_ca_file")
    if config["auth"]["mode"] not in {"token_file", "existing_bootstrap"}:
        raise ValueError("Mode natif explicite requis")
    if "s3_ca_file" in config["auth"]:
        # Forme seule ici ; le fichier est validé au lancement du bootstrap.
        if config["auth"]["mode"] != "existing_bootstrap" or not (
            type(config["auth"]["s3_ca_file"]) is str
            and Path(config["auth"]["s3_ca_file"]).is_absolute()
        ):
            raise ValueError("CA S3 : chemin absolu, mode existing_bootstrap requis")
    if config["auth"]["mode"] == "existing_bootstrap" and config["auth"]["token_file"]:
        raise ValueError("Pas de fallback ni token alternatif")
    exact(config["tls"], "directory host pg_uid pg_gid")
    if not isinstance(config["tls"]["host"], str) or not config["tls"]["host"]:
        raise ValueError("SAN explicite requis")
    if any(
        type(config["tls"][key]) is not int or config["tls"][key] < 0
        for key in ("pg_uid", "pg_gid")
    ):
        raise ValueError("UID/GID PG observés requis")
    for key in (
        "settings_file",
        "compose_env_file",
        "carrier_dir",
        "pg_ca_file",
        "bootstrap_file",
        "initial_admin_file",
    ):
        if not Path(config[key]).is_absolute():
            raise ValueError("Chemin absolu requis")
    if config["settings_file"] == config["compose_env_file"]:
        raise ValueError("Interpolation Compose distincte des Settings")
    if Path(config["settings_file"]).name != ".env":
        raise ValueError(
            "Le fichier effectif du chargeur applicatif doit être .env dans son cwd privé"
        )
    return config


class Journal:
    """Intention/ACK immuables ; un ACK absent n'est jamais recréé."""

    def __init__(self, config):
        self.directory = Path(config["carrier_dir"])
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = self.directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
        ):
            raise ValueError("Répertoire carriers privé requis")
        self.binding = digest(config)
        path = self.directory / "binding.json"
        if not path.exists():
            private_write(path, canonical({"config_sha256": self.binding}))
        if json.loads(private_read(path)) != {"config_sha256": self.binding}:
            raise ValueError("Configuration changée : aucun rejeu")

    def read(self, name):
        return json.loads(private_read(self.directory / (name + ".json")))

    def exists(self, name):
        return (self.directory / (name + ".json")).exists()

    def write(self, name, value):
        private_write(self.directory / (name + ".json"), canonical(value))

    def run(self, name, operation):
        # Exclusif AVANT tout effet ; un échec laisse l'intention, jamais de retry.
        self.write(name + ".intent", {"binding": self.binding})
        result = operation()
        self.write(name + ".ack", result)
        return result

    def confirmed(self, name):
        intent = self.read(name + ".intent")
        if intent != {"binding": self.binding}:
            raise ValueError("Intention altérée")
        return self.read(name + ".ack")
