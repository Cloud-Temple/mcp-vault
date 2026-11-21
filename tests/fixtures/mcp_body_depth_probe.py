"""Sonde exécutée dans un PROCESSUS SÉPARÉ par `tests/test_mcp_body_bounds_118.py`.

Le processus parent l'arrête de l'extérieur s'il dépasse son échéance : un gel
du parseur ou d'un middleware ne peut donc pas bloquer la suite, et une
assertion de durée « après retour » n'est pas la seule garde.

Elle monte l'application RÉELLE (`server.create_app()` : middlewares de
journalisation, d'authentification, d'admin, PKI, rétention) sans lancer
OpenBao, puis envoie à `/mcp` :
  1. un corpus d'appels `secret_write` VALIDES dont `data` est imbriqué à
     différentes profondeurs, et deux racines extrêmes, tous ≤ 65 536 octets ;
  2. un appel normal après le corpus (le service est-il vivant ?) ;
  3. des requêtes sans jeton et avec un jeton invalide, en ASGI direct, en
     comptant les appels à `receive` (le corps est-il lu avant le refus ?).
Le résultat est écrit en JSON sur la sortie standard.
"""

import asyncio
import json
import os
import sys
import time

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(RACINE, "src"))
sys.path.insert(0, os.path.join(RACINE, "tests"))
import conftest  # noqa: E402,F401 — stub hvac déterministe si le vrai paquet manque

from unittest.mock import patch  # noqa: E402

from starlette.testclient import TestClient  # noqa: E402

CLE = os.environ["ADMIN_BOOTSTRAP_KEY"]
LIMITE = 65536


def _appel_secret_write(profondeur):
    # Construit à la main : `json.dumps` lui-même récurse et échoue au-delà
    # d'environ 1 000 niveaux, bien avant la borne d'octets.
    data = '{"k":' * profondeur + '"v"' + "}" * profondeur
    return ('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"secret_write",'
            '"arguments":{"vault_id":"sonde-118","path":"p","data":' + data + "}}}")


def _classer(reponse):
    try:
        corps = reponse.json()
    except Exception:
        texte = reponse.text
        for ligne in texte.splitlines():  # réponse en flux SSE
            if ligne.startswith("data:"):
                corps = json.loads(ligne[5:])
                break
        else:
            return "illisible"
    if "result" in corps:
        return "traite"
    code = corps.get("error", {}).get("code")
    if code == -32700:
        return "parse_error"
    if code == -32602:
        return "invalid_params"
    return f"erreur_{code}"


def main():
    from mcp_vault import server

    entetes = {"Authorization": f"Bearer {CLE}", "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream", "Host": "localhost"}
    sortie = {"corpus": [], "racines": []}
    with patch.object(server, "_install_vault_lifespan", lambda app: None):
        app = server.create_app()

    with TestClient(app, base_url="http://localhost") as client:
        for profondeur in (8, 32, 64, 128, 200, 256, 1000, 10000):
            corps = _appel_secret_write(profondeur).encode()
            if len(corps) > LIMITE:
                continue
            debut = time.perf_counter()
            r = client.post("/mcp", content=corps, headers=entetes)
            sortie["corpus"].append({"profondeur": profondeur, "octets": len(corps),
                                     "statut": r.status_code, "classe": _classer(r),
                                     "ms": round((time.perf_counter() - debut) * 1000, 1)})
        for nom, n in (("tableau", 32767), ("objet", 10922)):
            corps = ("[" * n + "0" + "]" * n if nom == "tableau"
                     else '{"a":' * n + "0" + "}" * n).encode()
            debut = time.perf_counter()
            r = client.post("/mcp", content=corps, headers=entetes)
            sortie["racines"].append({"forme": nom, "octets": len(corps),
                                      "statut": r.status_code, "classe": _classer(r),
                                      "ms": round((time.perf_counter() - debut) * 1000, 1)})
        r = client.post("/mcp", headers=entetes, content=json.dumps(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}).encode())
        sortie["apres"] = {"statut": r.status_code, "classe": _classer(r)}

    async def sans_lecture(jeton):
        lectures = []
        envoyes = []

        async def receive():
            lectures.append(1)
            return {"type": "http.request", "body": b"{}" * 40000, "more_body": False}

        async def send(evenement):
            envoyes.append(evenement)

        h = [(b"host", b"localhost"), (b"content-type", b"application/json")]
        if jeton is not None:
            h.append((b"authorization", b"Bearer " + jeton.encode()))
        scope = {"type": "http", "method": "POST", "path": "/mcp", "raw_path": b"/mcp",
                 "query_string": b"", "headers": h, "scheme": "http",
                 "server": ("localhost", 8030), "client": ("127.0.0.1", 1),
                 "http_version": "1.1", "asgi": {"version": "3.0"}, "root_path": ""}
        await app(scope, receive, send)
        statut = next(e["status"] for e in envoyes if e["type"] == "http.response.start")
        return {"statut": statut, "lectures_du_corps": len(lectures)}

    sortie["sans_jeton"] = asyncio.run(sans_lecture(None))
    sortie["jeton_invalide"] = asyncio.run(sans_lecture("jeton-invalide-118"))
    print(json.dumps(sortie))


if __name__ == "__main__":
    main()
