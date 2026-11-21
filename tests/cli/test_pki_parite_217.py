"""#217 — commandes CLI PKI ajoutées pour la parité : `pki sign-csr`, `pki status`,
et l'affichage de `crl_next_update` par `pki ca-key`.

Chaque test vérifie ce qui part vers le serveur (outil MCP et arguments exacts, ou
requête HTTP exacte) et ce qui est rendu à l'utilisateur (fichiers écrits à
l'identique, code de sortie). Un test qui ne regarderait que la sortie texte
resterait vert si la commande n'appelait plus rien.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from cli.commands import cli

CSR = ("-----BEGIN CERTIFICATE REQUEST-----\n"
       "MIIBNTCB3AIBADBQMQswCQYDVQQGEwJGUjEWMBQGA1UEChMNQ2xvdWQgVGVtcGxl\n"
       "-----END CERTIFICATE REQUEST-----\n")
CERT = "-----BEGIN CERTIFICATE-----\nCERTLIGNE1\nCERTLIGNE2\n-----END CERTIFICATE-----\n"
CHAIN = "-----BEGIN CERTIFICATE-----\nINTERMEDIAIRE\n-----END CERTIFICATE-----\n"
SIGNE = {"status": "ok", "dns_name": "pg-01.dbaas.example.test", "serial_number": "12:34",
         "certificate": CERT, "ca_chain": CHAIN, "not_after": "2027-02-19T00:00:00+00:00",
         "root_fingerprint_sha256": "AA:BB"}
STATUT = {"status": "ok", "initialized": True, "root_expires": "2051-01-01T00:00:00+00:00",
          "root_fingerprint_sha256": "AA:BB", "int_expires": "2027-11-21T00:00:00+00:00",
          "crl_next_update": "2026-11-28T22:00:00+00:00", "csr_domain": "dbaas.example.test",
          "csr_ttl": "2160h", "cert_count": 3, "acme_enabled": False, "eab_policy": None,
          "eab_required": False, "crl_url": "https://pki.example.test/pki/ca/crl.pem"}


def _invoquer(args, reponse, entree=None):
    appel = AsyncMock(return_value=reponse)
    client = MagicMock()
    client.call_tool = appel
    with patch("cli.commands.MCPClient", return_value=client):
        resultat = CliRunner().invoke(cli, args, input=entree)
    return resultat, appel


def test_sign_csr_envoie_le_fichier_exact_et_ecrit_les_pem_a_l_identique(tmp_path):
    csr = tmp_path / "pg.csr"
    csr.write_text(CSR)
    cert, chaine = tmp_path / "pg.crt", tmp_path / "chain.pem"
    resultat, appel = _invoquer(["pki", "sign-csr", str(csr), "--cert-out", str(cert),
                                 "--chain-out", str(chaine)], SIGNE)
    assert resultat.exit_code == 0, resultat.output
    appel.assert_awaited_once_with("pki_sign_csr", {"csr": CSR})
    assert cert.read_bytes() == CERT.encode()
    assert chaine.read_bytes() == CHAIN.encode()
    assert "pg-01.dbaas.example.test" in resultat.output


def test_sign_csr_lit_l_entree_standard():
    resultat, appel = _invoquer(["pki", "sign-csr", "-"], SIGNE, entree=CSR)
    assert resultat.exit_code == 0, resultat.output
    appel.assert_awaited_once_with("pki_sign_csr", {"csr": CSR})


def test_sign_csr_refusee_code_non_nul_et_aucun_fichier(tmp_path):
    csr = tmp_path / "pg.csr"
    csr.write_text(CSR)
    cert = tmp_path / "pg.crt"
    refus = {"status": "error", "error_type": "csr_rejected", "message": "CSR refusée : 2 SAN"}
    resultat, appel = _invoquer(["pki", "sign-csr", str(csr), "--cert-out", str(cert)], refus)
    assert appel.await_count == 1
    assert resultat.exit_code == 1, resultat.output
    assert not cert.exists()


def test_status_interroge_l_api_admin_et_affiche_crl_et_csr():
    reponse = MagicMock()
    reponse.json.return_value = STATUT
    http = AsyncMock()
    http.get = AsyncMock(return_value=reponse)
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=None)
    with patch("httpx.AsyncClient", return_value=http):
        resultat = CliRunner().invoke(
            cli, ["--url", "https://vault.example.test", "--token", "jeton-test", "pki", "status"])
    assert resultat.exit_code == 0, resultat.output
    http.get.assert_awaited_once()
    url = http.get.call_args.args[0]
    assert url == "https://vault.example.test/admin/api/pki/status"
    assert http.get.call_args.kwargs["headers"] == {"Authorization": "Bearer jeton-test"}
    assert "2026-11-28T22:00:00+00:00" in resultat.output
    assert "dbaas.example.test" in resultat.output
    assert "fermé" in resultat.output


def test_ca_key_affiche_l_echeance_de_la_crl():
    reponse = {"status": "ok", "pem": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
               "sha256_fingerprint": "AA:BB", "expires": "2051-01-01T00:00:00+00:00",
               "crl_next_update": "2026-11-28T22:00:00+00:00",
               "url": "https://pki.example.test/pki/ca/root.pem"}
    resultat, appel = _invoquer(["pki", "ca-key"], reponse)
    assert resultat.exit_code == 0, resultat.output
    appel.assert_awaited_once_with("pki_ca_public_key", {})
    assert "2026-11-28T22:00:00+00:00" in resultat.output
