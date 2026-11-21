"""#118 — ce qui protège /mcp une fois sorti de Coraza.

Coraza bornait la PROFONDEUR des corps JSON de /mcp (`SecRequestBodyJsonDepthLimit
32` + règle 10011). /mcp ne passant plus par Coraza, cette garde doit exister
ailleurs. Ces tests établissent, sur l'application RÉELLE (`create_app()` et
tous ses middlewares), que :

1. un appel `secret_write` VALIDE dont `data` est imbriqué jusqu'à 128 niveaux
   atteint la primitive `write_secret`, qui reçoit `data` à la profondeur
   envoyée, et rend un résultat sans erreur d'outil ;
2. au-delà, le SDK MCP refuse en « Parse error » (-32700), vite, sans 5xx ;
   et le refus est monotone : une profondeur supérieure n'est jamais acceptée ;
3. deux racines extrêmes de 64 Kio (tableau, objet) sont refusées ;
4. le service répond normalement après le corpus ;
5. sans jeton ou avec un jeton invalide (mode `bearer`), le refus 401 tombe
   SANS LIRE LE CORPS : aucun octet n'est parsé avant authentification.
   Le mode `bearer-anonymous` (exception documentée #116, S3 seulement) n'est
   pas couvert par cette garantie.

La sonde tourne dans un processus séparé, ARRÊTÉ de l'extérieur à l'échéance :
un gel ne peut pas bloquer la suite, et l'assertion de durée n'est pas la
seule garde. La borne d'OCTETS (65 536) est, elle, portée par le Caddyfile et
qualifiée par le banc WAF réel (`waf/tests/`).
"""

import json
import os
import subprocess
import sys

import pytest

SONDE = os.path.join(os.path.dirname(__file__), "fixtures", "mcp_body_depth_probe.py")
ECHEANCE_S = 120
BUDGET_MS = 1000


@pytest.fixture(scope="module")
def mesure():
    try:
        import starlette.testclient  # noqa: F401
        from mcp.server import MCPServer  # noqa: F401
    except ImportError as e:  # pragma: no cover — environnement incomplet
        pytest.fail(f"dépendances d'exécution absentes : {e}")
    env = dict(os.environ)
    for cle in [k for k in env if k.startswith(("METADATA_", "HUB_VAULT_", "AUDIT_"))]:
        env.pop(cle)
    env.update({
        "ADMIN_BOOTSTRAP_KEY": "Sonde-118-Cle-Bootstrap-Assez-Longue-Pour-Valider-2026",
        "MCP_AUTH_MODE": "bearer",
        "S3_ENDPOINT_URL": "http://127.0.0.1:1",
        "S3_ACCESS_KEY_ID": "sonde", "S3_SECRET_ACCESS_KEY": "sonde", "S3_BUCKET_NAME": "sonde",
    })
    try:
        fini = subprocess.run([sys.executable, SONDE], env=env, capture_output=True,
                              text=True, timeout=ECHEANCE_S)
    except subprocess.TimeoutExpired:
        pytest.fail(f"la sonde n'a pas rendu la main en {ECHEANCE_S} s : gel")
    assert fini.returncode == 0, fini.stderr[-3000:]
    return json.loads(fini.stdout.strip().splitlines()[-1])


def test_aucune_reponse_lente_ni_5xx(mesure):
    for cas in mesure["corpus"] + mesure["racines"]:
        assert cas["statut"] < 500, cas
        assert cas["ms"] < BUDGET_MS, cas


def test_imbrication_raisonnable_atteint_la_primitive(mesure):
    par_profondeur = {c["profondeur"]: c for c in mesure["corpus"]}
    for profondeur in (8, 32, 64, 128):
        cas = par_profondeur[profondeur]
        assert (cas["statut"], cas["classe"]) == (200, "resultat"), cas
        assert cas["primitive"] == [profondeur], cas


def test_imbrication_excessive_refusee_et_refus_monotone(mesure):
    corpus = sorted(mesure["corpus"], key=lambda c: c["profondeur"])
    classes = [c["classe"] for c in corpus]
    assert set(classes) <= {"resultat", "parse_error"}, classes
    premier_refus = classes.index("parse_error")  # lève si rien n'est refusé
    assert all(c == "parse_error" for c in classes[premier_refus:]), classes
    assert all(c["primitive"] == [] for c in corpus[premier_refus:]), corpus
    plus_profond = max(mesure["corpus"], key=lambda c: c["profondeur"])
    assert plus_profond["profondeur"] >= 10000 and plus_profond["statut"] == 400


def test_racines_extremes_refusees(mesure):
    assert [r["forme"] for r in mesure["racines"]] == ["tableau", "objet"]
    for cas in mesure["racines"]:
        assert cas["octets"] <= 65536, cas
        assert (cas["statut"], cas["classe"]) == (400, "parse_error"), cas


def test_service_vivant_apres_le_corpus(mesure):
    assert mesure["apres"] == {"statut": 200, "classe": "resultat"}


@pytest.mark.parametrize("cas", ["sans_jeton", "jeton_invalide"])
def test_refus_d_authentification_sans_lire_le_corps(mesure, cas):
    assert mesure[cas] == {"statut": 401, "lectures_du_corps": 0}
