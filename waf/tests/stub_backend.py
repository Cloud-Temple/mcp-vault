"""Backend factice du banc WAF.

Chaque requête est journalisée DÈS SON ENTRÉE dans le handler, avant toute
lecture du corps : un journal vide prouve donc l'absence de contact, pas
seulement l'absence de requête complète. Le compteur `body_len` progresse au
fil de la lecture et `etat` distingue :
  - `en_cours`   la requête est entrée, son corps n'est pas fini de lire ;
  - `complet`    le corps a été lu jusqu'au bout ;
  - `interrompu` le flux a été coupé avant la fin annoncée.

`GET /__stub/log` rend le journal ; `DELETE /__stub/log` le rend puis le vide.
L'en-tête `X-Stub-Status` impose le statut de réponse (relais des 401/403).
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
LOCK = threading.Lock()
BLOC = 4096


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        if self.path == "/__stub/log":
            with LOCK:
                out = json.dumps(LOG).encode()
                if self.command == "DELETE":
                    LOG.clear()
            return self._reply(200, out)
        entree = {"method": self.command, "target": self.path, "body_len": 0, "etat": "en_cours"}
        with LOCK:
            LOG.append(entree)
        try:
            self._read_body(entree)
            entree["etat"] = "complet"
        except Exception:
            entree["etat"] = "interrompu"
            self.close_connection = True
            return
        status = int(self.headers.get("X-Stub-Status") or 200)
        self._reply(status, json.dumps({"stub": "reached", "target": self.path}).encode())

    def _lire(self, n, entree):
        while n > 0:
            morceau = self.rfile.read(min(n, BLOC))
            if not morceau:
                raise EOFError("flux coupé")
            entree["body_len"] += len(morceau)
            n -= len(morceau)

    def _read_body(self, entree):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                ligne = self.rfile.readline()
                if not ligne:
                    raise EOFError("flux coupé")
                taille = int(ligne.split(b";")[0].strip() or b"0", 16)
                if taille == 0:
                    self.rfile.readline()
                    return
                self._lire(taille, entree)
                self.rfile.readline()
        self._lire(int(self.headers.get("Content-Length") or 0), entree)

    def _reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8030), Handler).serve_forever()
