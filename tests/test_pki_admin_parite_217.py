"""#217 — routes PKI de l'API admin ajoutées pour la parité avec MCP.

- `POST /admin/api/pki/sign-csr` : admin seulement, corps validé AVANT tout appel
  métier, codes HTTP alignés sur les refus de `sign_csr`, audit S3 sans PEM, et
  raccord à la frontière d'audit PostgreSQL (admission, clôture, réponse retenue).
- `GET /admin/api/pki/certs?limit=&offset=` : pagination bornée, défaut inchangé.

Chaque refus vérifie aussi que la fonction métier N'A PAS été appelée : un test
qui ne regarderait que le code HTTP resterait vert si le refus arrivait après
la signature.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcp_vault.admin import api
from mcp_vault.storage import audit_call, audit_http
from mcp_vault.storage.audit_contract import TOOLS
from mcp_vault.storage.audit_pg import current_audit_call
from mcp_vault.storage.postgres import MutationUnknown
from mcp_vault.vault import pki_ca

CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
CERT = "-----BEGIN CERTIFICATE-----\nCANARI-CERTIFICAT\n-----END CERTIFICATE-----\n"
CHAIN = "-----BEGIN CERTIFICATE-----\nCANARI-CHAINE\n-----END CERTIFICATE-----\n"
SIGNE = {"status": "ok", "dns_name": "pg-01.dbaas.example.test", "serial_number": "12:34",
         "certificate": CERT, "ca_chain": CHAIN, "not_after": "2027-02-19T00:00:00+00:00",
         "root_fingerprint_sha256": "AA:BB"}
ADMIN = {"client_name": "admin", "permissions": ["read", "write", "admin"],
         "allowed_resources": [], "token_hash": "t"}
ECRITURE = {"client_name": "ecrivain", "permissions": ["read", "write"],
            "allowed_resources": [], "token_hash": "t"}


def _appel(path, method="GET", body=b"", jeton=ADMIN, query=b""):
    events = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(event):
        events.append(event)

    scope = {"type": "http", "method": method, "path": path, "query_string": query,
             "headers": [(b"authorization", b"Bearer t")]}
    with patch.object(api, "_get_token_info", return_value=jeton):
        asyncio.run(api.handle_admin_api(scope, receive, send, None))
    start = next(e for e in events if e["type"] == "http.response.start")
    corps = next(e for e in events if e["type"] == "http.response.body")
    return start["status"], json.loads(corps["body"])


# ── Signature de CSR ────────────────────────────────────────────────────────


def test_signature_refusee_sans_droit_admin_et_sans_appel_metier():
    with patch.object(pki_ca, "sign_csr", AsyncMock(return_value=SIGNE)) as signe:
        code, _ = _appel("/admin/api/pki/sign-csr", "POST",
                         json.dumps({"csr": CSR}).encode(), jeton=ECRITURE)
    assert code == 403
    signe.assert_not_awaited()


@pytest.mark.parametrize("corps", [b"", b"pas du json", b"[]", b'{"csr": 12}', b'{"csr": "  "}',
                                   b'{"autre": "x"}', b"\xff\xfe"])
def test_corps_invalide_400_sans_appel_metier(corps):
    with patch.object(pki_ca, "sign_csr", AsyncMock(return_value=SIGNE)) as signe:
        code, reponse = _appel("/admin/api/pki/sign-csr", "POST", corps)
    assert code == 400 and reponse["error_type"] == "invalid_input"
    signe.assert_not_awaited()


def test_signature_transmet_la_csr_exacte_et_audite_sans_pem():
    with patch.object(pki_ca, "sign_csr", AsyncMock(return_value=SIGNE)) as signe, \
            patch.object(api, "log_audit") as audit:
        code, reponse = _appel("/admin/api/pki/sign-csr", "POST", json.dumps({"csr": CSR}).encode())
    assert code == 200 and reponse == SIGNE
    signe.assert_awaited_once_with(CSR)
    audit.assert_called_once()
    outil, statut = audit.call_args.args[:2]
    detail = audit.call_args.kwargs["detail"]
    assert (outil, statut) == ("pki_sign_csr", "ok")
    assert "pg-01.dbaas.example.test" in detail and "12:34" in detail   # présence d'abord
    trace = repr(audit.call_args)
    assert "CANARI" not in trace and "CERTIFICATE" not in trace and "MIIB" not in trace


@pytest.mark.parametrize("error_type,code_attendu", [
    ("csr_rejected", 400), ("feature_disabled", 400), ("invalid_input", 400),
    ("backend_error", 500), ("ttl_truncated", 500), ("issuer_expires_too_soon", 500),
])
def test_codes_http_alignes_sur_les_refus_de_sign_csr(error_type, code_attendu):
    refus = {"status": "error", "error_type": error_type, "message": "refus"}
    with patch.object(pki_ca, "sign_csr", AsyncMock(return_value=refus)), \
            patch.object(api, "log_audit") as audit:
        code, reponse = _appel("/admin/api/pki/sign-csr", "POST", json.dumps({"csr": CSR}).encode())
    assert code == code_attendu and reponse == refus
    assert audit.call_args.args[:2] == ("pki_sign_csr", "error")
    assert error_type in audit.call_args.kwargs["detail"]


def test_route_de_signature_raccordee_a_l_audit_postgresql():
    assert audit_http.route({"method": "POST", "path": "/admin/api/pki/sign-csr"}) == ("pki_sign_csr", "")
    assert "pki_sign_csr" in TOOLS
    assert audit_http.route({"method": "GET", "path": "/admin/api/pki/sign-csr"}) is None


def _pg(terminal=None, admission=None):
    settings = SimpleNamespace(metadata_backend="postgres")
    return (patch.object(api, "_get_token_info", return_value={"auth_type": "token", "permissions": ["admin"]}),
            patch.object(audit_http, "get_settings", return_value=settings),
            patch.object(audit_call, "get_settings", return_value=settings),
            patch.object(audit_call, "make_call",
                         side_effect=lambda tool, vid: SimpleNamespace(call_id="fixed", tool=tool)),
            patch.object(audit_call, "admit", admission or AsyncMock()),
            patch.object(audit_call, "append", terminal or AsyncMock()))


def _executer_pg(patches, signe):
    sent = []

    async def receive():
        return {"type": "http.request", "body": json.dumps({"csr": CSR}).encode()}

    async def exercise():
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                patch.object(pki_ca, "sign_csr", signe):
            await api._handle_authenticated_admin(
                {"method": "POST", "path": "/admin/api/pki/sign-csr",
                 "headers": [(b"authorization", b"Bearer synthetic")]},
                receive, AsyncMock(side_effect=sent.append), None)
    asyncio.run(exercise())
    return sent


def test_postgresql_signature_dans_l_appel_audite_puis_cloture():
    vu = []

    async def signer(csr):
        vu.append(current_audit_call.get().tool)
        return SIGNE
    terminal = AsyncMock()
    sent = _executer_pg(_pg(terminal=terminal), AsyncMock(side_effect=signer))
    assert vu == ["pki_sign_csr"]                       # l'appel métier est DANS l'appel audité
    assert terminal.call_args.args[0].tool == "pki_sign_csr"
    assert terminal.call_args.args[1:] == ("public_terminal", "completed")
    assert "CANARI" not in repr(terminal.call_args)
    assert sent[0]["status"] == 200 and json.loads(sent[1]["body"])["certificate"] == CERT


def test_postgresql_admission_impossible_aucune_signature():
    from mcp_vault.storage.postgres import MetadataUnavailable
    signe = AsyncMock(return_value=SIGNE)
    sent = _executer_pg(_pg(admission=AsyncMock(side_effect=MetadataUnavailable("offline"))), signe)
    signe.assert_not_awaited()
    assert sent[0]["status"] == 503


def test_postgresql_cloture_incertaine_certificat_retenu_sans_rejeu():
    signe = AsyncMock(return_value=SIGNE)
    sent = _executer_pg(_pg(terminal=AsyncMock(side_effect=MutationUnknown("fixed"))), signe)
    signe.assert_awaited_once()
    corps = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 503
    assert corps["replay_allowed"] is False
    assert "CANARI" not in repr(sent)


# ── Pagination de l'inventaire ──────────────────────────────────────────────


@pytest.mark.parametrize("query,attendu", [
    (b"", (200, 0)), (b"limit=50", (50, 0)), (b"offset=400", (200, 400)),
    (b"limit=1000&offset=7", (1000, 7)), (b"limit=1", (1, 0)),
])
def test_pagination_transmise(query, attendu):
    inventaire = {"status": "ok", "certs": [], "total": 0}
    with patch.object(pki_ca, "list_issued_certs", AsyncMock(return_value=inventaire)) as lister:
        code, _ = _appel("/admin/api/pki/certs", query=query)
    assert code == 200
    lister.assert_awaited_once_with(limit=attendu[0], offset=attendu[1])


@pytest.mark.parametrize("query", [b"limit=0", b"limit=1001", b"limit=-1", b"limit=abc", b"limit=1.5",
                                   b"offset=-3", b"limit=10&limit=20", b"limit=", b"offset=%D9%A5",
                                   b"limit=" + b"9" * 5000, b"offset=" + b"1" * 10])
def test_pagination_invalide_400_sans_appel(query):
    with patch.object(pki_ca, "list_issued_certs", AsyncMock()) as lister:
        code, reponse = _appel("/admin/api/pki/certs", query=query)
    assert code == 400 and reponse["error_type"] == "invalid_input"
    lister.assert_not_awaited()
