"""CA S3 explicite du bootstrap natif : aucune connexion, aucun service lancé."""

import datetime
import json
import os
import sys
from pathlib import Path

import pytest

from .test_standalone_operator_187 import private, synthetic_config

ROOT = Path(__file__).resolve().parents[1]
CLOSED_ENV = {"PATH", "PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"}


@pytest.fixture
def scripts(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import standalone_pg_files
    import standalone_pg_native

    return standalone_pg_files, standalone_pg_native


def make_ca_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-s3-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def bootstrap_config(tmp_path, *, ca=None):
    tmp_path.chmod(0o700)
    config = synthetic_config(tmp_path)
    config["auth"] = {"mode": "existing_bootstrap", "token_file": ""}
    if ca is not None:
        config["auth"]["s3_ca_file"] = str(ca)
    return config


@pytest.fixture
def ca_file(tmp_path):
    path = tmp_path / "s3-ca.pem"
    private(path, make_ca_pem()[0].decode())
    return path


class Spy:
    """Remplace subprocess.run : jamais d'enfant, jamais de connexion."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return type("Done", (), {"stdout": b"synthetic-root\n"})()


def refuse_launch(monkeypatch, module):
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **kw: pytest.fail("Aucun lancement avec une CA refusée"),
    )


def test_explicit_ca_is_the_only_variable_added_to_the_child(
    scripts, tmp_path, monkeypatch, ca_file
):
    _files, native = scripts
    spy = Spy()
    monkeypatch.setattr(native.subprocess, "run", spy)
    for name, value in {
        "AWS_CA_BUNDLE": "/evil/ca.pem",
        "SSL_CERT_FILE": "/evil/ssl.pem",
        "REQUESTS_CA_BUNDLE": "/evil/req.pem",
        "HTTPS_PROXY": "http://evil:3128",
        "AWS_ACCESS_KEY_ID": "AKIAEVIL",
        "AWS_PROFILE": "evil",
        "S3_ENDPOINT_URL": "https://evil",
    }.items():
        monkeypatch.setenv(name, value)

    config = bootstrap_config(tmp_path, ca=ca_file)
    assert native.native_token(config) == "synthetic-root"

    ((argv, kwargs),) = spy.calls
    assert kwargs["env"] == {
        "PATH": os.defpath,
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "AWS_CA_BUNDLE": str(ca_file),
    }
    assert argv == [
        sys.executable,
        str(ROOT / "scripts/standalone_pg_bootstrap.py"),
        config["settings_file"],
    ]
    assert kwargs["cwd"] == Path(config["settings_file"]).parent


def test_absent_ca_keeps_the_closed_environment_strictly(
    scripts, tmp_path, monkeypatch
):
    _files, native = scripts
    spy = Spy()
    monkeypatch.setattr(native.subprocess, "run", spy)
    monkeypatch.setenv("AWS_CA_BUNDLE", "/evil/ca.pem")

    native.native_token(bootstrap_config(tmp_path))

    ((_argv, kwargs),) = spy.calls
    assert kwargs["env"] == {
        "PATH": os.defpath,
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    assert set(kwargs["env"]) == CLOSED_ENV


@pytest.mark.parametrize(
    "defect",
    [
        "relative",
        "empty",
        "missing",
        "directory",
        "symlink",
        "group-readable",
        "world-readable",
        "other-owner",
        "parent-open",
        "oversize",
        "not-pem",
        "empty-file",
        "blank-file",
        "private-key-only",
        "truncated-pem",
    ],
)
def test_invalid_ca_is_refused_before_any_launch(
    scripts, tmp_path, monkeypatch, defect
):
    _files, native = scripts
    refuse_launch(monkeypatch, native)
    pem, key = make_ca_pem()
    target = tmp_path / "s3-ca.pem"
    path = target
    if defect == "relative":
        private(target, pem.decode())
        monkeypatch.chdir(tmp_path)
        path = "s3-ca.pem"
    elif defect == "empty":
        path = ""
    elif defect == "directory":
        target.mkdir(mode=0o700)
    elif defect == "symlink":
        real = tmp_path / "real.pem"
        private(real, pem.decode())
        target.symlink_to(real)
    elif defect in {"group-readable", "world-readable"}:
        private(target, pem.decode())
        target.chmod(0o640 if defect == "group-readable" else 0o604)
    elif defect == "other-owner":
        private(target, pem.decode())
        monkeypatch.setattr(os, "geteuid", lambda: os.stat(target).st_uid + 1)
    elif defect == "parent-open":
        private(target, pem.decode())
    elif defect == "oversize":
        private(target, pem.decode() + "# " + "x" * 70000 + "\n")
    elif defect == "not-pem":
        private(target, "synthetic text, no certificate\n")
    elif defect == "empty-file":
        private(target, "")
    elif defect == "blank-file":
        private(target, " \n\n")
    elif defect == "private-key-only":
        private(target, key.decode())
    elif defect == "truncated-pem":
        private(target, pem.decode()[: len(pem) // 2])
    config = bootstrap_config(tmp_path, ca=path)
    if defect == "parent-open":
        tmp_path.chmod(0o755)
    try:
        with pytest.raises((ValueError, OSError)):
            native.native_token(config)
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.parametrize("value", [None, 7, ["/a"], {"p": 1}, True])
def test_non_string_ca_is_refused_before_any_launch(
    scripts, tmp_path, monkeypatch, value
):
    _files, native = scripts
    refuse_launch(monkeypatch, native)
    config = bootstrap_config(tmp_path)
    config["auth"]["s3_ca_file"] = value
    with pytest.raises(ValueError):
        native.native_token(config)


def test_ca_with_token_file_mode_is_refused(scripts, tmp_path, monkeypatch, ca_file):
    files, native = scripts
    refuse_launch(monkeypatch, native)
    config = synthetic_config(tmp_path)
    config["auth"]["s3_ca_file"] = str(ca_file)
    private(tmp_path / "token", "native-synthetic")
    with pytest.raises(ValueError):
        native.native_token(config)
    path = tmp_path / "operator.json"
    private(path, json.dumps(config))
    with pytest.raises(ValueError):
        files.load_config(path)


def test_load_config_accepts_old_and_new_shapes(scripts, tmp_path, ca_file):
    files, _native = scripts
    path = tmp_path / "operator.json"

    old = bootstrap_config(tmp_path)
    private(path, json.dumps(old))
    assert files.load_config(path)["auth"] == {
        "mode": "existing_bootstrap",
        "token_file": "",
    }

    token = synthetic_config(tmp_path)
    path.unlink()
    private(path, json.dumps(token))
    assert files.load_config(path)["auth"]["mode"] == "token_file"

    new = bootstrap_config(tmp_path, ca=ca_file)
    path.unlink()
    private(path, json.dumps(new))
    assert files.load_config(path)["auth"]["s3_ca_file"] == str(ca_file)


@pytest.mark.parametrize("value", ["relative.pem", "", 3, None])
def test_load_config_refuses_malformed_ca_value(scripts, tmp_path, value):
    files, _native = scripts
    config = bootstrap_config(tmp_path)
    config["auth"]["s3_ca_file"] = value
    path = tmp_path / "operator.json"
    private(path, json.dumps(config))
    with pytest.raises(ValueError):
        files.load_config(path)


def test_load_config_still_refuses_unknown_auth_field(scripts, tmp_path, ca_file):
    files, _native = scripts
    config = bootstrap_config(tmp_path, ca=ca_file)
    config["auth"]["verify"] = False
    path = tmp_path / "operator.json"
    private(path, json.dumps(config))
    with pytest.raises(ValueError):
        files.load_config(path)


def test_config_binding_unchanged_without_the_option(scripts, tmp_path):
    """Journal.binding digère la config : l'ancienne forme garde son empreinte."""
    files, _native = scripts
    config = bootstrap_config(tmp_path)
    assert "s3_ca_file" not in config["auth"]
    assert files.digest(config) == files.digest(json.loads(json.dumps(config)))


def test_real_settings_accept_external_ca_and_real_s3_client_uses_it(
    scripts, tmp_path, monkeypatch, ca_file
):
    """VRAIS Settings Vault : AWS_CA_BUNDLE externe, hors .env (extra=forbid).

    Le téléchargement est intercepté AVANT toute connexion ; le vrai client S3
    est seulement construit, jamais utilisé.
    """
    import standalone_pg_bootstrap

    from mcp_vault import s3_client
    from mcp_vault.config import get_settings
    from mcp_vault.openbao import lifecycle

    private(
        tmp_path / ".env",
        "ADMIN_BOOTSTRAP_KEY=synthetic-bootstrap\n"
        "S3_BUCKET_NAME=synthetic-bucket\n"
        "S3_ENDPOINT_URL=https://s3.synthetic.invalid\n"
        "S3_ACCESS_KEY_ID=synthetic\n"
        "S3_SECRET_ACCESS_KEY=synthetic\n",
    )
    observed = []

    def download():
        s3_client.reset_clients()
        client = s3_client.get_s3_data_client()
        observed.append(
            (os.environ.get("AWS_CA_BUNDLE"), client._endpoint.http_session._verify)
        )
        s3_client.reset_clients()
        return {"root_token": "native-root", "keys": ["gone"]}

    monkeypatch.setattr(
        os,
        "environ",
        {"PATH": os.defpath, "AWS_CA_BUNDLE": str(ca_file)},
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lifecycle, "_download_encrypted_keys_from_s3", download)
    try:
        assert standalone_pg_bootstrap.load_root(tmp_path / ".env") == "native-root"
        assert get_settings().s3_bucket_name == "synthetic-bucket"
    finally:
        get_settings.cache_clear()
        s3_client.reset_clients()
    assert observed == [(str(ca_file), str(ca_file))]


# --- FIFO sans écrivain : la CA ne doit jamais bloquer le chargement -----------

FIFO_CHILD = r"""
import json, os, sys
sys.path.insert(0, sys.argv[2])
import standalone_pg_files as files
mode, fifo = sys.argv[1], sys.argv[3]
opened, readers = [], []
real_open, real_fdopen = os.open, os.fdopen
def spy_open(path, flags, *a, **kw):
    opened.append(str(path))
    return real_open(path, flags, *a, **kw)
def spy_fdopen(*a, **kw):
    readers.append(1)
    return real_fdopen(*a, **kw)
os.open, os.fdopen = spy_open, spy_fdopen
if mode == "race":
    # lstat annonce un fichier régulier : seul le fstat du descripteur ouvert
    # peut encore refuser le FIFO.
    regular = os.stat(sys.argv[4])
    real_lstat = files.Path.lstat
    files.Path.lstat = lambda self: regular if str(self) == fifo else real_lstat(self)
try:
    files.s3_ca_bundle(fifo)
    outcome = "ACCEPTED"
except ValueError as error:
    outcome = "REFUSED:" + str(error)
print(json.dumps({"outcome": outcome, "opened": opened, "fdopen": len(readers)}))
"""


def run_fifo_child(mode, fifo, extra=()):
    """Enfant Python court, borné par le superviseur : un blocage échoue, il ne gèle pas."""
    import subprocess

    child = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            FIFO_CHILD,
            mode,
            str(ROOT / "scripts"),
            str(fifo),
            *extra,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        out, err = child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=5)
        pytest.fail("s3_ca_bundle bloque sur un FIFO sans écrivain")
    assert child.returncode == 0, err.decode()
    return json.loads(out)


@pytest.fixture
def fifo(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "ca-no-writer.fifo"
    os.mkfifo(path, 0o600)
    return path


def test_fifo_without_writer_is_refused_before_any_open(fifo):
    result = run_fifo_child("plain", fifo)
    assert result["outcome"].startswith("REFUSED:Fichier privé régulier")
    assert str(fifo) not in result["opened"]
    assert result["fdopen"] == 0


def test_fifo_swapped_after_lstat_is_refused_by_the_descriptor_check(fifo, tmp_path):
    regular = tmp_path / "regular.pem"
    private(regular, make_ca_pem()[0].decode())
    result = run_fifo_child("race", fifo, extra=(str(regular),))
    assert result["outcome"].startswith("REFUSED:Fichier privé régulier")
    assert str(fifo) in result["opened"]


def test_private_read_nonblocking_is_keyword_only_and_reads_regular_files(
    scripts, tmp_path
):
    files, _native = scripts
    tmp_path.chmod(0o700)
    path = tmp_path / "private.bin"
    private(path, "synthetic")
    assert files.private_read(path) == b"synthetic"
    assert files.private_read(path, nonblocking=True) == b"synthetic"
    with pytest.raises(TypeError):
        files.private_read(path, True)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        files.private_read(path, nonblocking=True)
