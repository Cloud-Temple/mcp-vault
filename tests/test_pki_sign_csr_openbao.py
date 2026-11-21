#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Issue #206 — signature de CSR, durées configurables, rôle restreint : contre un
OpenBao RÉEL (`bao server -dev`, binaire de l'image de test).

Pourquoi un vrai OpenBao : les comportements qui motivent ce lot sont ceux du
moteur, mesurés sur 2.5.1, et aucune doublure ne les reproduit fidèlement —
`/sign/<rôle>` ACCEPTE une CSR à deux SAN, IGNORE une demande d'usage CA, et
TRONQUE silencieusement un TTL supérieur au plafond du rôle ou du mount (une
racine demandée à 25 ans sort à 10 ans sur un mount de 10 ans).

⚠️ Pas de vert à vide. Sous `MCP_VAULT_TEST_BAO_REQUIRED=1` (posé par le stage
`test` du Dockerfile, donc en CI) : `bao` absent, `openssl` absent, vrai `hvac`
absent ou OpenBao qui ne démarre pas ⇒ ÉCHEC, jamais skip. Sans ce drapeau (poste
de développement sans `bao`), skip explicite.

La chaîne est vérifiée par `openssl verify` avec la SEULE racine comme ancre, le
cas du client qui ne garde que la racine (modèle AWS RDS) ; chaque vérification
positive a son témoin négatif, pour que le test discrimine.
"""
import asyncio
import base64
import ipaddress
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from tests.conftest import admin_auth_context, auth_context

_REQUIRED = os.getenv("MCP_VAULT_TEST_BAO_REQUIRED") == "1"
_DOMAIN = "dbaas.example.test"
_HOUR = 3600
_ROOT_MOUNT, _INT_MOUNT = "_sys_pki_root", "_sys_pki_int"


def _need(binary: str) -> str:
    path = shutil.which(binary)
    if path:
        return path
    if _REQUIRED:
        pytest.fail(f"`{binary}` absent alors que MCP_VAULT_TEST_BAO_REQUIRED=1")
    pytest.skip(f"`{binary}` absent : test OpenBao réel non exécuté sur ce poste")


@pytest.fixture(scope="module")
def bao():
    bao_bin = _need("bao")
    _need("openssl")
    import hvac
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # `bao server -dev` écrit le jeton dans ~/.vault-token et MEURT après unseal si
    # HOME n'est pas inscriptible (cas de l'utilisateur `mcp` de l'image) : mesuré.
    home = tempfile.mkdtemp(prefix="bao-home-")
    token = uuid.uuid4().hex
    log_path = os.path.join(home, "bao.log")
    log = open(log_path, "w")
    proc = subprocess.Popen(
        [bao_bin, "server", "-dev", f"-dev-root-token-id={token}",
         f"-dev-listen-address=127.0.0.1:{port}"],
        stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "HOME": home})
    addr = f"http://127.0.0.1:{port}"
    try:
        client = hvac.Client(url=addr, token=token)
    except Exception as e:  # stub hvac du conftest (#64) : pas d'OpenBao réel possible
        proc.kill()
        if _REQUIRED:
            pytest.fail(f"vrai hvac requis : {e}")
        pytest.skip("vrai hvac absent")
    deadline = time.monotonic() + 30
    while True:
        try:
            if client.is_authenticated():
                break
        except Exception:
            pass
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            with open(log_path) as f:
                pytest.fail(f"OpenBao de test non démarré :\n{f.read()[-1500:]}")
        time.sleep(0.2)
    yield SimpleNamespace(addr=addr, token=token, client=client)
    proc.terminate()
    proc.wait(timeout=15)
    log.close()
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture
def pki(bao):
    """PKI vierge à chaque test, `pki_ca` branché sur l'OpenBao réel."""
    for mount in (_ROOT_MOUNT, _INT_MOUNT):
        bao.client.sys.disable_secrets_engine(path=mount)
    settings = SimpleNamespace(
        openbao_addr=bao.addr, pki_base_url=bao.addr, pki_base_url_validated=bao.addr,
        allowed_hosts_list=[], pki_csr_domain=_DOMAIN, pki_csr_ttl="2160h")
    with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=bao.client), \
            patch("mcp_vault.vault.pki_ca.get_settings", return_value=settings), \
            patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
            admin_auth_context():
        yield SimpleNamespace(bao=bao, settings=settings)


# ── Outils ──────────────────────────────────────────────────────────────────

async def _setup(**ttls):
    from mcp_vault.vault.pki_ca import setup_pki_ca
    result = await setup_pki_ca(lab_mode=True, allowed_domains=["example.test"], **ttls)
    assert result["status"] == "ok", result
    return result


def _csr(*names, cn=None, key=None, ips=(), uris=(), ca=False, key_cert_sign=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []))
    general = ([x509.DNSName(n) for n in names]
               + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
               + [x509.UniformResourceIdentifier(u) for u in uris])
    if general:
        builder = builder.add_extension(x509.SubjectAlternativeName(general), critical=False)
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    if key_cert_sign:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def _name() -> str:
    return f"{uuid.uuid4()}.{_DOMAIN}"


def _cert_count(client) -> int:
    listed = client.list(f"{_INT_MOUNT}/certs")
    return len(listed["data"]["keys"]) if listed else 0


def _mount_max(client, mount) -> int:
    tune = client.sys.read_mount_configuration(path=mount)
    return int(tune.get("data", tune)["max_lease_ttl"])


def _default_issuer(client) -> str:
    return client.read(f"{_INT_MOUNT}/config/issuers")["data"]["default"]


def _issuer_count(client) -> int:
    return len(client.list(f"{_INT_MOUNT}/issuers")["data"]["keys"])


def _lifetime_hours(pem: str) -> float:
    cert = x509.load_pem_x509_certificate(pem.encode())
    return (cert.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / _HOUR


def _patch_json(bao, path: str, body: dict) -> None:
    """PATCH (merge) natif OpenBao : modifie UN champ sans réinitialiser les autres."""
    import requests
    resp = requests.patch(f"{bao.addr}/v1/{path}", json=body, timeout=10, headers={
        "X-Vault-Token": bao.token, "Content-Type": "application/merge-patch+json"})
    assert resp.status_code in (200, 204), resp.text


async def _root_pem() -> str:
    from mcp_vault.vault.pki_ca import get_ca_root_pem
    root = await get_ca_root_pem()
    assert root["status"] == "ok", root
    return root["pem"]


async def _int_pem() -> str:
    from mcp_vault.vault.pki_ca import _read_pem_url
    return await _read_pem_url(f"{_INT_MOUNT}/ca/pem")


def _openssl_verify(tmp_path, root_pem: str, leaf_pem: str, chain_pem: str = "") -> bool:
    """`openssl verify` avec la racine pour SEULE ancre ; `chain_pem` = non approuvé."""
    tag = uuid.uuid4().hex[:8]
    root, leaf = tmp_path / f"root-{tag}.pem", tmp_path / f"leaf-{tag}.pem"
    root.write_text(root_pem)
    leaf.write_text(leaf_pem)
    cmd = ["openssl", "verify", "-purpose", "sslserver", "-CAfile", str(root)]
    if chain_pem:
        chain = tmp_path / f"chain-{tag}.pem"
        chain.write_text(chain_pem)
        cmd += ["-untrusted", str(chain)]
    return subprocess.run(cmd + [str(leaf)], capture_output=True, text=True).returncode == 0


async def _sign(csr_pem: str) -> dict:
    from mcp_vault.vault.pki_ca import sign_csr
    return await sign_csr(csr_pem)


# ── 1. Durées configurables ─────────────────────────────────────────────────

async def test_racine_25_ans_intermediaire_1_an_et_plafonds_des_mounts(pki):
    """Sans le réglage du plafond, la racine sortait à 10 ans (mesuré)."""
    result = await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    assert result["root_created"] is True
    assert 219000 - 1 <= _lifetime_hours(await _root_pem()) <= 219000
    assert 8760 - 1 <= _lifetime_hours(await _int_pem()) <= 8760
    assert _mount_max(client, _ROOT_MOUNT) == 219000 * _HOUR
    assert _mount_max(client, _INT_MOUNT) == 8760 * _HOUR


async def test_defauts_historiques_inchanges(pki):
    await _setup()
    client = pki.bao.client
    assert 87600 - 1 <= _lifetime_hours(await _root_pem()) <= 87600
    assert 43800 - 1 <= _lifetime_hours(await _int_pem()) <= 43800
    assert _mount_max(client, _ROOT_MOUNT) == 87600 * _HOUR
    assert _mount_max(client, _INT_MOUNT) == 43800 * _HOUR


async def test_second_setup_sans_duree_conserve_la_pki_existante(pki):
    """#214 : rejouer le setup préserve également l'émetteur et sa chaîne."""
    from mcp_vault.vault.pki_ca import _read_pem_url
    await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    root_before, issuer_before = await _root_pem(), _default_issuer(client)
    chain_before = await _read_pem_url(f"{_INT_MOUNT}/ca_chain")
    count_before = _issuer_count(client)

    again = await _setup()

    assert again["root_created"] is False
    assert await _root_pem() == root_before
    assert again["root_expires"] == x509.load_pem_x509_certificate(
        root_before.encode()).not_valid_after_utc.isoformat()
    assert _mount_max(client, _ROOT_MOUNT) == 219000 * _HOUR
    assert _mount_max(client, _INT_MOUNT) == 8760 * _HOUR
    assert _default_issuer(client) == issuer_before
    assert _issuer_count(client) == count_before
    assert await _read_pem_url(f"{_INT_MOUNT}/ca_chain") == chain_before
    assert 8760 - 1 <= _lifetime_hours(await _int_pem()) <= 8760


async def test_durees_explicites_sur_pki_existante_reglent_les_plafonds(pki):
    """Sur une PKI neuve le mount naît au bon plafond ; ici il EXISTE déjà (10 / 5 ans).

    La racine n'est pas régénérée (`root_created: false`), mais son plafond est
    relevé : sans cela, chaque intermédiaire signé ensuite serait tronqué au
    plafond hérité, silencieusement (mesuré).
    """
    await _setup()
    client = pki.bao.client
    root_before = await _root_pem()
    int_before = await _int_pem()

    result = await _setup(root_ttl="219000h", int_ttl="8760h")

    assert result["root_created"] is False and await _root_pem() == root_before
    assert _mount_max(client, _ROOT_MOUNT) == 219000 * _HOUR
    assert _mount_max(client, _INT_MOUNT) == 8760 * _HOUR
    assert await _int_pem() == int_before


@pytest.mark.parametrize("default", ["", "introuvable", None])
async def test_setup_refuse_un_etat_emetteur_ambigu(pki, default):
    from mcp_vault.vault.pki_ca import setup_pki_ca

    await _setup(acme=False)
    client = pki.bao.client
    before = (_default_issuer(client), _issuer_count(client))
    read = client.read

    def read_issuers(path):
        if path == f"{_INT_MOUNT}/config/issuers":
            return {"data": {"default": default}}
        if path == f"{_INT_MOUNT}/issuer/default" and default == "introuvable":
            return None
        return read(path)

    with patch.object(client, "read", side_effect=read_issuers):
        result = await setup_pki_ca(acme=False)

    assert result["status"] == "error", result
    assert (_default_issuer(client), _issuer_count(client)) == before


async def test_rejeu_migre_la_crl_sans_rotation_intermediaire(pki):
    from mcp_vault.vault.pki_ca import get_ca_root_pem

    await _setup(acme=False)
    client = pki.bao.client
    issuer_before = _default_issuer(client)
    client.write(f"{_INT_MOUNT}/config/crl", expiry="72h", auto_rebuild=False)
    assert client.read(f"{_INT_MOUNT}/crl/rotate")["data"]["success"] is True

    await _setup(acme=False)

    config = client.read(f"{_INT_MOUNT}/config/crl")["data"]
    assert config["expiry"] == "168h" and config["auto_rebuild"] is True
    assert config["auto_rebuild_grace_period"] == "72h" and config["disable"] is False
    assert _default_issuer(client) == issuer_before
    root = await get_ca_root_pem()
    expiry = datetime.fromisoformat(root["crl_next_update"])
    assert timedelta(hours=167) < expiry - datetime.now(timezone.utc) <= timedelta(hours=168)
    await _setup(acme=False)
    assert (await get_ca_root_pem())["crl_next_update"] == root["crl_next_update"]


async def test_crl_se_renouvelle_sans_revocation(pki, monkeypatch):
    from mcp_vault.vault import pki_ca

    # Garder une marge supérieure à un cycle du moteur OpenBao.
    monkeypatch.setattr(pki_ca, "_INTERMEDIATE_CRL_CONFIG", {
        **pki_ca._INTERMEDIATE_CRL_CONFIG, "expiry": "120s", "auto_rebuild_grace_period": "115s",
    })
    await _setup(acme=False)
    first = await pki_ca._read_intermediate_crl()
    assert first.next_update_utc > datetime.now(timezone.utc)
    assert len(first) == 0
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        await asyncio.sleep(1)
        current = await pki_ca._read_intermediate_crl()
        if current.next_update_utc > first.next_update_utc:
            assert current.next_update_utc > datetime.now(timezone.utc)
            assert current.last_update_utc <= first.next_update_utc
            assert len(current) == 0
            return
    pytest.fail("OpenBao n’a pas renouvelé la CRL avant la fin du délai de test")


async def test_revocation_met_a_jour_immediatement_la_crl(pki):
    from mcp_vault.vault.pki_ca import _read_intermediate_crl, revoke_cert

    await _setup(acme=False)
    leaf = await _sign(_csr(_name())[0])
    assert leaf["status"] == "ok", leaf
    serial = int(leaf["serial_number"].replace(":", ""), 16)
    assert (await _read_intermediate_crl()).get_revoked_certificate_by_serial_number(serial) is None

    result = await revoke_cert(leaf["serial_number"])

    assert result["status"] == "ok" and result["crl_updated"] is True, result
    assert (await _read_intermediate_crl()).get_revoked_certificate_by_serial_number(serial) is not None


async def test_durees_incoherentes_refusees_sans_rien_monter(pki):
    from mcp_vault.vault.pki_ca import setup_pki_ca
    for ttls in ({"root_ttl": "8760h", "int_ttl": "8760h"},
                 {"root_ttl": "1000h", "int_ttl": "2000h"},
                 {"int_ttl": "100h"},            # leaf_ttl 720h ≥ int_ttl
                 {"root_ttl": "25 ans"}):
        result = await setup_pki_ca(lab_mode=True, allowed_domains=["example.test"], **ttls)
        assert result["status"] == "error" and result["error_type"] == "invalid_input", (ttls, result)
    mounts = pki.bao.client.sys.list_mounted_secrets_engines()
    assert f"{_ROOT_MOUNT}/" not in mounts.get("data", mounts)


# ── 2-3. Signature nominale et chaîne ───────────────────────────────────────

async def test_csr_ec_p256_signee_cle_conservee_et_chaine_verifiee_par_la_seule_racine(pki, tmp_path):
    await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    name = _name()
    csr_pem, key = _csr(name, cn=name)
    before = _cert_count(client)

    result = await _sign(csr_pem)

    assert result["status"] == "ok", result
    assert "private_key" not in result
    cert = x509.load_pem_x509_certificate(result["certificate"].encode())
    sans = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    assert [type(s) for s in sans] == [x509.DNSName] and sans[0].value == name
    try:
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    except x509.ExtensionNotFound:
        pass
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    assert (cert.public_key().public_bytes(serialization.Encoding.DER, pub)
            == key.public_key().public_bytes(serialization.Encoding.DER, pub))
    assert _lifetime_hours(result["certificate"]) >= 2160 - 1 / _HOUR
    chain = x509.load_pem_x509_certificates(result["ca_chain"].encode())
    assert len(chain) == 1 and chain[0].subject != chain[0].issuer, "chaîne sans la racine"
    root_pem = await _root_pem()
    root = x509.load_pem_x509_certificate(root_pem.encode())
    assert result["root_fingerprint_sha256"] == ":".join(
        f"{b:02X}" for b in root.fingerprint(hashes.SHA256()))
    assert _cert_count(client) == before + 1

    assert _openssl_verify(tmp_path, root_pem, result["certificate"], result["ca_chain"])
    # Témoins : sans l'intermédiaire, ou avec une autre racine, la vérification échoue.
    assert not _openssl_verify(tmp_path, root_pem, result["certificate"])
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autre racine")])
    other_root = (x509.CertificateBuilder().subject_name(other_name).issuer_name(other_name)
                  .public_key(other_key.public_key()).serial_number(1)
                  .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                  .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .sign(other_key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM).decode()
    assert not _openssl_verify(tmp_path, other_root, result["certificate"], result["ca_chain"])


# ── 4. Refus réels, sans émission ───────────────────────────────────────────

def _tampered(csr_pem: str) -> str:
    der = bytearray(x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01  # dernier octet de la signature
    body = base64.encodebytes(bytes(der)).decode()
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{body}-----END CERTIFICATE REQUEST-----\n"


async def test_csr_non_conformes_refusees_sans_aucune_emission(pki):
    await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    n = _name()
    ok_pem, _ = _csr(n)
    key_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    cases = {
        "deux SAN": _csr(n, _name())[0],
        "CN différent du SAN": _csr(n, cn=_name())[0],
        "CN sans SAN": _csr(cn=n)[0],
        "joker": _csr(f"*.{_DOMAIN}")[0],
        "SAN IP": _csr(n, ips=["10.0.0.1"])[0],
        "SAN URI": _csr(n, uris=["https://x.example.test/"])[0],
        "autre domaine": _csr("a1.evil.test")[0],
        "domaine nu": _csr(_DOMAIN)[0],
        "suffixe trompeur (tiret)": _csr(f"evil-{_DOMAIN}")[0],
        "suffixe trompeur (domaine ajouté)": _csr(f"a1.{_DOMAIN}.evil.test")[0],
        "majuscules": _csr(n.upper())[0],
        "usage CA (BasicConstraints)": _csr(n, ca=True)[0],
        "usage CA (keyCertSign)": _csr(n, key_cert_sign=True)[0],
        "clé RSA": _csr(n, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))[0],
        "clé EC P-224": _csr(n, key=ec.generate_private_key(ec.SECP224R1()))[0],
        "signature altérée": _tampered(ok_pem),
        "PEM invalide": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----",
        "deux CSR concaténées": ok_pem + _csr(_name())[0],
        "clé privée au lieu d'une CSR": key_pem,
        "vide": "",
        "trop grande": "-----BEGIN CERTIFICATE REQUEST-----\n" + "A" * 20000 + "\n-----END CERTIFICATE REQUEST-----",
    }
    before = _cert_count(client)
    failures = {}
    for label, pem in cases.items():
        result = await _sign(pem)
        if result.get("error_type") != "csr_rejected" or "certificate" in result:
            failures[label] = result
    assert not failures, failures
    assert _cert_count(client) == before, "un refus ne doit rien émettre"
    # Le témoin conforme, lui, passe : les refus ne viennent pas d'un banc cassé.
    assert (await _sign(ok_pem))["status"] == "ok"


async def test_fonction_desactivee_sans_domaine_configure(pki):
    await _setup()
    pki.settings.pki_csr_domain = ""
    before = _cert_count(pki.bao.client)
    result = await _sign(_csr(_name())[0])
    assert result["error_type"] == "feature_disabled"
    assert _cert_count(pki.bao.client) == before
    roles = pki.bao.client.list(f"{_INT_MOUNT}/roles")["data"]["keys"]
    assert "csr-servers" not in roles


async def test_role_csr_expose_par_acme_refus_sans_emission(pki):
    """Revue de plan R2 : la façade ACME, non authentifiée, ne doit pas servir csr-servers."""
    await _setup()
    client = pki.bao.client
    assert (await _sign(_csr(_name())[0]))["status"] == "ok"  # crée le rôle
    acme = {"enabled": True, "default_directory_policy": "role:acme-servers",
            "allowed_issuers": ["*"], "eab_policy": "not-required"}
    for roles in (["acme-servers", "csr-servers"], ["*"]):
        client.write(f"{_INT_MOUNT}/config/acme", allowed_roles=roles, **acme)
        before = _cert_count(client)
        result = await _sign(_csr(_name())[0])
        assert result["error_type"] == "unsafe_configuration", (roles, result)
        assert _cert_count(client) == before
    await _setup()  # restreint ACME à acme-servers
    assert (await _sign(_csr(_name())[0]))["status"] == "ok"


@pytest.mark.parametrize("enabled,directory_policy", [(True, "forbid"), (False, "sign-verbatim")])
async def test_joker_refuse_si_le_marqueur_de_fermeture_est_incomplet(pki, enabled, directory_policy):
    await _setup()
    client = pki.bao.client
    client.write(f"{_INT_MOUNT}/config/acme", allowed_roles=["*"], enabled=enabled,
                 default_directory_policy=directory_policy, eab_policy="always-required")
    before = _cert_count(client)
    result = await _sign(_csr(_name())[0])
    assert result["error_type"] == "unsafe_configuration", result
    assert _cert_count(client) == before


# ── 5. Autorisations : un jeton dédié qui ne sait QUE signer ────────────────

def _policy_store():
    from mcp_vault.auth.policies import PolicyStore
    store = PolicyStore(SimpleNamespace(s3_endpoint_url="http://localhost:0",
                                        s3_bucket_name="test-bucket"))
    store._save = MagicMock(return_value=True)
    store._maybe_refresh = MagicMock()
    store._available = True
    for pid, allowed, denied in (
            ("dbaas-pki-sign", ["pki_sign_csr"], []),
            ("tout-permis", [], []),
            ("joker-pki", ["pki_*"], []),
            ("joker", ["*"], []),
            ("refus-prioritaire", ["pki_sign_csr"], ["pki_sign_csr"])):
        created = store.create(pid, allowed_tools=allowed, denied_tools=denied)
        assert created.get("status") == "created", created  # le catalogue connaît l'outil
    return store


def _token(policy_id="dbaas-pki-sign", permissions=("write",)):
    return {"client_name": "dbaas-control", "permissions": list(permissions),
            "allowed_resources": [], "policy_id": policy_id, "auth_type": "token"}


async def test_jeton_dedie_signe_et_ne_peut_rien_d_autre(pki):
    from mcp_vault import server
    await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    store = _policy_store()
    with patch("mcp_vault.auth.policies.get_policy_store", return_value=store):
        with auth_context(_token()):
            ok = await server.pki_sign_csr(csr=_csr(_name())[0])
            assert ok["status"] == "ok", ok
            before = _cert_count(client)
            protected = {
                "pki_issue_cert": server.pki_issue_cert(common_name=f"m.{_DOMAIN}"),
                "pki_ca_setup": server.pki_ca_setup(lab_mode=False, allowed_domains="evil.test"),
                "pki_ca_rotate_intermediate": server.pki_ca_rotate_intermediate(),
                "pki_revoke_cert": server.pki_revoke_cert(serial_number=ok["serial_number"]),
                "secret_read": server.secret_read(vault_id="dbaas", path="x"),
                "secret_write": server.secret_write(vault_id="dbaas", path="x", data={"a": "b"}),
                "vault_create": server.vault_create(vault_id="dbaas-evil"),
                "vault_list": server.vault_list(),
                "policy_create": server.policy_create(policy_id="evil", allowed_tools=["*"]),
                "token_update": server.token_update(hash_prefix="abcdef123456", permissions="admin"),
            }
            leaks = {}
            for tool, call in protected.items():
                result = await call
                if result.get("status") != "error" or result.get("error_type") != "permission_denied":
                    leaks[tool] = result
            assert not leaks, leaks
            assert _cert_count(client) == before

        refused = {
            "write sans policy": _token(policy_id=""),
            "read + policy dédiée": _token(permissions=("read",)),
            "policy vide (tout permis)": _token("tout-permis"),
            "joker pki_*": _token("joker-pki"),
            "joker *": _token("joker"),
            "refus prioritaire": _token("refus-prioritaire"),
            "policy absente du store": _token("inconnue"),
        }
        leaks = {}
        for label, token in refused.items():
            with auth_context(token):
                result = await server.pki_sign_csr(csr=_csr(_name())[0])
            if result.get("status") != "error" or "certificate" in result:
                leaks[label] = result
        assert not leaks, leaks

        store._available = False
        with auth_context(_token()):
            result = await server.pki_sign_csr(csr=_csr(_name())[0])
        assert result["error_type"] == "policy_store_unavailable", result
    assert _cert_count(client) == before


# ── 6. Rotation transparente pour un client qui ne garde que la racine ──────

async def test_rotation_intermediaire_transparente_pour_un_client_racine_seule(pki, tmp_path):
    from mcp_vault.vault.pki_ca import rotate_intermediate
    await _setup(root_ttl="219000h", int_ttl="8760h")
    client = pki.bao.client
    root_pem = await _root_pem()
    a = await _sign(_csr(_name())[0])

    # Durée DIFFÉRENTE du setup (revue du diff) : sinon le réglage du plafond par
    # la rotation n'est pas prouvé.
    rotated = await rotate_intermediate(int_ttl="4380h")
    assert rotated["status"] == "ok", rotated
    assert 4380 - 1 <= _lifetime_hours(await _int_pem()) <= 4380
    assert _mount_max(client, _INT_MOUNT) == 4380 * _HOUR
    b = await _sign(_csr(_name())[0])
    again = await rotate_intermediate()  # sans durée : le nouveau plafond est conservé
    assert again["status"] == "ok", again
    c = await _sign(_csr(_name())[0])

    assert len({a["ca_chain"], b["ca_chain"], c["ca_chain"]}) == 3, "un intermédiaire par rotation"
    assert await _root_pem() == root_pem
    assert a["root_fingerprint_sha256"] == b["root_fingerprint_sha256"] == c["root_fingerprint_sha256"]
    for signed in (a, b, c):
        assert _openssl_verify(tmp_path, root_pem, signed["certificate"], signed["ca_chain"])
    # Le certificat A ne dépend pas de l'intermédiaire courant : sa chaîne reste la sienne.
    assert not _openssl_verify(tmp_path, root_pem, a["certificate"], c["ca_chain"])
    assert 4380 - 1 <= _lifetime_hours(await _int_pem()) <= 4380
    assert _mount_max(client, _INT_MOUNT) == 4380 * _HOUR


# ── 7. Jamais de troncature silencieuse ─────────────────────────────────────

async def test_intermediaire_trop_court_refus_explicite(pki):
    await _setup(leaf_ttl="240h", int_ttl="720h")
    before = _cert_count(pki.bao.client)
    result = await _sign(_csr(_name())[0])
    assert result["error_type"] == "issuer_expires_too_soon", result
    assert "certificate" not in result
    assert _cert_count(pki.bao.client) == before


async def test_emetteur_qui_tronque_refuse_sur_les_deux_outils(pki):
    """Revue de plan R3 : émetteur réglé `truncate`, plafond du rôle ACME relevé."""
    from mcp_vault.vault.pki_ca import issue_certificate
    await _setup(leaf_ttl="240h", int_ttl="720h")
    client = pki.bao.client
    _patch_json(pki.bao, f"{_INT_MOUNT}/roles/acme-servers", {"max_ttl": "2160h"})
    _patch_json(pki.bao, f"{_INT_MOUNT}/issuer/{_default_issuer(client)}",
                {"leaf_not_after_behavior": "truncate"})

    signed = await _sign(_csr(_name())[0])
    issued = await issue_certificate(f"m.{_DOMAIN}", ttl="2160h")

    for result in (signed, issued):
        assert result["error_type"] == "ttl_truncated", result
        assert "certificate" not in result and "private_key" not in result


async def test_rotation_tronquee_par_le_plafond_racine_rien_n_est_importe(pki):
    from mcp_vault.vault.pki_ca import rotate_intermediate
    await _setup(leaf_ttl="240h", root_ttl="8000h", int_ttl="2000h")
    client = pki.bao.client
    client.sys.tune_mount_configuration(path=_ROOT_MOUNT, max_lease_ttl="3000h")
    state = (_default_issuer(client), _issuer_count(client), _mount_max(client, _INT_MOUNT))

    result = await rotate_intermediate(int_ttl="5000h")

    assert result["error_type"] == "ttl_truncated", result
    assert (_default_issuer(client), _issuer_count(client),
            _mount_max(client, _INT_MOUNT)) == state


async def test_rotation_au_dela_de_la_fin_de_racine_rien_n_est_importe(pki):
    from mcp_vault.vault.pki_ca import rotate_intermediate
    await _setup(leaf_ttl="240h", root_ttl="4000h", int_ttl="2000h")
    client = pki.bao.client
    client.sys.tune_mount_configuration(path=_ROOT_MOUNT, max_lease_ttl="87600h")
    state = (_default_issuer(client), _issuer_count(client), _mount_max(client, _INT_MOUNT))

    result = await rotate_intermediate(int_ttl="5000h")

    # Mesuré : OpenBao SIGNE un intermédiaire de 5000 h sous une racine de 4000 h.
    # La chaîne mourrait avec la racine, avant les certificats : refus explicite.
    assert result["error_type"] == "issuer_expires_too_soon", result
    assert (_default_issuer(client), _issuer_count(client),
            _mount_max(client, _INT_MOUNT)) == state


async def test_pki_heritee_intermediaire_au_dela_de_la_racine_aucune_feuille_remise(pki):
    """Hiérarchie antérieure au correctif : un intermédiaire qui survit à la racine
    (OpenBao le signe, mesuré). Une feuille couverte par l'intermédiaire mais pas
    par la racine cesserait d'être vérifiable : refus sur les deux outils."""
    from mcp_vault.vault.pki_ca import issue_certificate
    await _setup(leaf_ttl="240h", root_ttl="4000h", int_ttl="2000h")
    client = pki.bao.client
    # Construction « à l'ancienne », sans le contrôle d'import de #206.
    client.sys.tune_mount_configuration(path=_ROOT_MOUNT, max_lease_ttl="87600h")
    client.sys.tune_mount_configuration(path=_INT_MOUNT, max_lease_ttl="87600h")
    csr = client.write(f"{_INT_MOUNT}/intermediate/generate/internal", common_name="Héritée",
                       key_type="rsa", key_bits=2048, add_basic_constraints=True)["data"]["csr"]
    signed = client.write(f"{_ROOT_MOUNT}/issuer/mcp-vault-root/sign-intermediate",
                          csr=csr, format="pem_bundle", ttl="5000h")["data"]["certificate"]
    new_id = client.write(f"{_INT_MOUNT}/intermediate/set-signed",
                          certificate=signed)["data"]["imported_issuers"][0]
    client.write(f"{_INT_MOUNT}/config/issuers", default=new_id)
    _patch_json(pki.bao, f"{_INT_MOUNT}/roles/acme-servers", {"max_ttl": "4500h"})
    pki.settings.pki_csr_ttl = "4500h"

    issued = await issue_certificate(f"m.{_DOMAIN}", ttl="4500h")
    signed_csr = await _sign(_csr(_name())[0])

    for result in (issued, signed_csr):
        assert result["error_type"] == "issuer_expires_too_soon", result
        assert "certificate" not in result and "private_key" not in result


@pytest.mark.parametrize("acme_response", [
    {"data": {}},
    {"data": {"allowed_roles": ""}},
    {"data": {"allowed_roles": {}}},
    {"data": {"allowed_roles": [""]}},
    {"data": {"allowed_roles": [None]}},
    {"data": None},
    {},
    "inattendu",
])
async def test_config_acme_malformee_refus_ferme_sans_ecrire_le_role(acme_response):
    """Revue du diff : une réponse que le contrat OpenBao ne prévoit pas n'est pas
    une liste vide. Seul le 404 (None) passe ; ici, rien n'est écrit ni signé.
    Doublure délibérée : un OpenBao réel ne produit pas ces formes."""
    from mcp_vault.vault import pki_ca
    client = MagicMock()
    client.read = MagicMock(return_value=acme_response)
    settings = SimpleNamespace(pki_csr_domain=_DOMAIN, pki_csr_ttl="2160h")
    with patch.object(pki_ca, "_get_hvac_client", return_value=client), \
            patch.object(pki_ca, "get_settings", return_value=settings), \
            patch.object(pki_ca, "is_pki_initialized", return_value=True), \
            admin_auth_context():
        result = await pki_ca.sign_csr(_csr(_name())[0])
    assert result["error_type"] == "unsafe_configuration", result
    client.write.assert_not_called()


def test_controle_de_duree_refuse_un_certificat_raccourci_de_60_secondes():
    """Témoin hors OpenBao : la tolérance est d'une seconde, pas de cinq minutes."""
    from mcp_vault.vault.pki_ca import _validity_shortfall
    from tests.pki_doubles import make_cert
    t0 = datetime.now(timezone.utc)
    shortened = x509.load_pem_x509_certificate(make_cert(90 * 86400 - 60, ca=False).encode())
    complete = x509.load_pem_x509_certificate(make_cert(90 * 86400 + 1, ca=False).encode())
    assert _validity_shortfall(shortened, t0, 90 * 86400)
    assert _validity_shortfall(complete, t0, 90 * 86400) is None


async def _check_acme_http(pki, *, enabled, role="acme-servers"):
    import httpx
    from mcp_vault.pki_middleware import PkiMiddleware

    async def unexpected_route(scope, receive, send):
        pytest.fail(f"Route PKI non interceptée : {scope['path']}")

    transport = httpx.ASGITransport(app=PkiMiddleware(unexpected_route))
    with patch("mcp_vault.pki_middleware.get_settings", return_value=pki.settings):
        async with httpx.AsyncClient(transport=transport, base_url="http://pki.test") as http:
            for prefix in ("/acme", f"/v1/{_INT_MOUNT}/acme",
                           f"/v1/{_INT_MOUNT}/roles/{role}/acme"):
                directory = await http.get(f"{prefix}/directory")
                if enabled:
                    assert directory.status_code == 200, directory.text
                    assert directory.json()["newAccount"]
                else:
                    for response in (directory, await http.post(f"{prefix}/new-account", json={}),
                                     await http.post(f"{prefix}/new-order", json={})):
                        assert response.status_code == 404, (response.url, response.text)
            root = await http.get("/pki/ca/root.pem")
            assert root.status_code == 200 and "BEGIN CERTIFICATE" in root.text


async def test_setup_sans_acme_et_rejeu_avec_signature_reelle(pki, tmp_path):
    from mcp_vault.vault.pki_ca import get_pki_status, setup_pki_ca

    client = pki.bao.client
    for options in ({"acme": False}, {"acme": False}, {"allowed_domains": ["example.test"]}):
        result = await setup_pki_ca(lab_mode=False, **options)
        assert result["status"] == "ok", result
        assert result["acme_enabled"] is False and result["acme_directory"] is None
        config = client.read(f"{_INT_MOUNT}/config/acme")["data"]
        assert config["enabled"] is False
        assert config["allowed_roles"] == ["*"]
        assert config["eab_policy"] == "always-required"
        assert client.read(f"{_INT_MOUNT}/roles/acme-servers") is None
        status = await get_pki_status()
        assert status["acme_enabled"] is False and status["acme_directory"] is None
        signed = await _sign(_csr(_name())[0])
        assert signed["status"] == "ok", signed
        assert _openssl_verify(tmp_path, await _root_pem(), signed["certificate"], signed["ca_chain"])
        assert client.read(f"{_INT_MOUNT}/roles/csr-servers") is not None
        await _check_acme_http(pki, enabled=False, role="csr-servers")


async def test_fermeture_et_reactivation_explicite_preservent_les_roles_tiers(pki):
    from mcp_vault.vault.pki_ca import setup_pki_ca

    await _setup()
    await _check_acme_http(pki, enabled=True)
    client = pki.bao.client
    root = await _root_pem()
    client.write(f"{_INT_MOUNT}/roles/partenaire", allowed_domains=["example.test"])
    client.write(f"{_INT_MOUNT}/config/acme", allowed_roles=["partenaire", "acme-servers"])
    closed = await setup_pki_ca(lab_mode=False, acme=False)
    assert closed["status"] == "ok", closed
    assert client.read(f"{_INT_MOUNT}/roles/acme-servers") is None
    assert client.read(f"{_INT_MOUNT}/roles/partenaire")["data"]["allowed_domains"] == ["example.test"]
    assert client.read(f"{_INT_MOUNT}/config/acme")["data"]["allowed_roles"] == ["partenaire"]
    await _check_acme_http(pki, enabled=False, role="partenaire")
    assert (await _setup(acme=True))["acme_enabled"] is True
    reopened = client.read(f"{_INT_MOUNT}/config/acme")["data"]
    assert reopened["allowed_roles"] == ["acme-servers", "partenaire"]
    assert reopened["eab_policy"] == "not-required"  # _setup réactive en mode lab.
    await _check_acme_http(pki, enabled=True)
    assert await _root_pem() == root


async def test_reprise_apres_fermeture_et_echec_de_suppression_du_role(pki):
    from mcp_vault.vault.pki_ca import setup_pki_ca

    await _setup()
    client = pki.bao.client
    with patch.object(client, "delete", side_effect=RuntimeError("suppression interrompue")):
        failed = await setup_pki_ca(lab_mode=False, acme=False)
    assert failed["status"] == "error"
    assert client.read(f"{_INT_MOUNT}/roles/acme-servers") is not None
    assert client.read(f"{_INT_MOUNT}/config/acme")["data"]["enabled"] is False
    await _check_acme_http(pki, enabled=False)
    assert (await _setup())["acme_enabled"] is False
    assert client.read(f"{_INT_MOUNT}/roles/acme-servers") is None
