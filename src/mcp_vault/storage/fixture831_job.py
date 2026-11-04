"""Processus propriétaire Vault831 fini et privé : aucune route, aucun outil MCP.

Même protocole que le job Agent831 : une ligne JSON par commande, numéros
strictement croissants, premier résultat inconnu = fin du transport sans
replay. Seules actions : `prepare_read` (writer A2) et `close`.

Deux credentials : le jeton opérateur Vault (autorisation, acteur, policy,
binding) et le jeton OpenBao dédié. Soit deux fichiers 0600 du compte courant
(`--bearer-file`, `Q831_BAO_READ_FILE`), soit `--stdin-credentials` : les deux
premières lignes de stdin, dans cet ordre, avant le protocole. Ce second mode
sert au lancement dans le conteneur Vault par `docker compose exec -T`, où les
fichiers de l'hôte ne sont pas visibles ; aucun credential n'y touche le disque.
Ce job ne démarre ni ne descelle OpenBao : il lit l'instance du serveur à
`openbao_addr`.

`--issue-bao-read-token --ttl-seconds S` (dans le conteneur Vault, une fois par
campagne) crée ce jeton OpenBao dédié : policy `q831-<nonce>-vault-read` de
`bao_read_policy`, jeton orphelin sans policy `default`, non renouvelable,
TTL S. Le root token est chargé en mémoire par la fonction du produit
(`openbao.lifecycle`, objet chiffré S3 et `ADMIN_BOOTSTRAP_KEY` du conteneur),
utilisé pour ces deux écritures puis oublié. Seul le jeton créé sort, sur
stdout ; le reçu (policy, sha256, accessor) va sur stderr. Un jeton créé mais
non conforme (policies inattendues, réponse incomplète) est révoqué par son
accessor avec le même root avant la sortie ; le reçu de refus porte l'accessor
et le résultat de la révocation.

`--revoke-bao-accessor A` (même conteneur, fin de campagne ou incident) révoque
le jeton du job par son accessor, lu dans le reçu d'émission. Le jeton lui-même
n'est jamais redemandé.

Garde d'émission : ces deux sous-commandes ne s'exécutent que si
`Q831_BAO_ISSUER_NONCE` vaut le nonce de la campagne. Seul le service compose
`vault831-<nonce>` porte cette variable : lancées dans le `mcp-vault` du banc ou
sur l'hôte, elles refusent avant de charger la moindre clé (code 2).

Le jeton OpenBao sert à deux lectures, et à elles seules (`bao_read_policy`) :
le secret de connexion PostgreSQL du rôle app (`metadata_pg_secret_path`), que
les stores PG relisent à chaque connexion, et les vingt canaries831. Le job
tient donc le mot de passe du rôle app PG pendant sa vie : même droit que l'ASGI
Vault, ni provisionneur, ni maintenance d'audit, ni écriture Bao. L'ouverture
n'est confirmée qu'après une vraie connexion PG faite avec ce jeton.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from contextlib import redirect_stdout
from pathlib import Path

LIMIT = 2 * 1024 * 1024
CREDENTIAL = 8192
TTL_MIN, TTL_MAX = 3600, 90 * 24 * 3600
ISSUER_ENV = "Q831_BAO_ISSUER_NONCE"
ACCESSOR = r"[A-Za-z0-9._-]{1,128}"


class IssuerNotArmed(RuntimeError):
    """Sous-commande root hors du service vault831-<nonce> : refus avant toute clé."""


class BaoTokenUnconfirmed(RuntimeError):
    """Jeton peut-être créé mais non conforme. Porte l'accessor et la révocation, jamais le jeton."""

    def __init__(self, accessor: str | None, revoked: bool):
        super().__init__("831 Bao token creation unconfirmed")
        self.accessor, self.revoked = accessor, revoked


def require_issuer(nonce: str, environ=None) -> None:
    """Garde explicite : la variable n'est posée que sur le service vault831-<nonce>."""
    value = (os.environ if environ is None else environ).get(ISSUER_ENV)
    if type(value) is not str or value != nonce:
        raise IssuerNotArmed("831 Bao issuer not armed for this nonce")


def read_private(path: Path) -> str:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError("831 private owner file required")
    value = path.read_text().strip()
    if not value or len(value.encode()) > 8192:
        raise ValueError("831 bounded owner credential required")
    return value


def bao_read_policy(*, nonce: str, pg_mount: str, pg_path: str) -> str:
    """Policy OpenBao exacte du jeton du job : 1 chemin PG app + 20 canaries, lecture seule.

    Chemins KV v2 explicites, sans glob : un autre tenant, un autre nonce, le
    provisionneur ou la maintenance d'audit restent refusés par OpenBao.
    """
    import re

    segment = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")
    if (not re.fullmatch("[0-9a-f]{12}", nonce) or not segment.fullmatch(pg_mount)
            or not pg_path or not all(segment.fullmatch(p) for p in pg_path.split("/"))):
        raise ValueError("831 exact Bao policy inputs required")
    paths = [f"{pg_mount}/data/{pg_path}"]
    paths += [f"q831-{nonce}-t{slot:02d}/data/q831/{nonce}/canary" for slot in range(20)]
    return "".join(f'path "{p}" {{\n  capabilities = ["read"]\n}}\n' for p in paths)


def read_stdin_credential(reader) -> str:
    """Une ligne de credential lue sur stdin : imprimable, bornée, jamais vide."""
    import re

    raw = reader.readline(CREDENTIAL + 2)
    if not raw.endswith(b"\n"):
        raise ValueError("831 bounded stdin credential required")
    value = raw[:-1].decode("ascii", "strict").strip()
    if not value or len(value) > CREDENTIAL or not re.fullmatch(r"[\x21-\x7e]+", value):
        raise ValueError("831 bounded stdin credential required")
    return value


def _settings(settings):
    if settings is None:
        from ..config import get_settings

        settings = get_settings()
    if settings.metadata_backend != "postgres":
        raise RuntimeError("831 Vault PostgreSQL metadata required")
    return settings


def _root_client(settings, load_init_keys):
    """Client hvac au root token du produit ; l'appelant remet `client.token` à vide."""
    import hvac

    if load_init_keys is None:
        from ..openbao.lifecycle import (
            _download_encrypted_keys_from_s3 as load_init_keys,
        )
    keys = load_init_keys()
    root = keys.get("root_token") if isinstance(keys, dict) else None
    del keys
    if type(root) is not str or not root:
        raise RuntimeError("831 OpenBao init keys unavailable")
    client = hvac.Client(url=settings.openbao_addr, token=root)
    del root
    return client


def _accessor_of(auth) -> str | None:
    import re

    value = auth.get("accessor") if isinstance(auth, dict) else None
    return value if type(value) is str and re.fullmatch(ACCESSOR, value) else None


def issue_bao_read_token(*, nonce: str, ttl_seconds: int, settings=None, load_init_keys=None, environ=None):
    """Policy versionnée puis jeton orphelin du job, avec le root token du produit.

    Retourne `(jeton, reçu)`. Le reçu ne contient aucun secret. Une policy du même
    nom déjà présente doit être identique à l'octet près, sinon refus avant tout
    jeton : une policy élargie à la main n'est jamais réutilisée. Un jeton créé
    dont la vérification échoue est révoqué par accessor avant `BaoTokenUnconfirmed`.
    """
    import hashlib

    import hvac

    require_issuer(nonce, environ)
    if type(ttl_seconds) is not int or not TTL_MIN <= ttl_seconds <= TTL_MAX:
        raise ValueError("831 Bao token TTL out of bounds")
    settings = _settings(settings)
    hcl = bao_read_policy(nonce=nonce, pg_mount=settings.metadata_pg_vault_id,
                         pg_path=settings.metadata_pg_secret_path)
    name = f"q831-{nonce}-vault-read"
    client = _root_client(settings, load_init_keys)
    try:
        try:
            current = client.sys.read_policy(name)
        except hvac.exceptions.InvalidPath:
            current = None
        if current is not None:
            rules = (current.get("data") or {}).get("rules", current.get("rules"))
            if rules != hcl:
                raise RuntimeError("831 existing Bao policy differs")
        else:
            client.sys.create_or_update_policy(name=name, policy=hcl)
        created = client.auth.token.create_orphan(
            policies=[name], no_default_policy=True, renewable=False, ttl=f"{ttl_seconds}s",
            explicit_max_ttl=f"{ttl_seconds}s", display_name=name)
        auth = created.get("auth") if isinstance(created, dict) else None
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if type(token) is not str or not token or sorted(auth.get("policies") or []) != [name]:
            # Revue P3-B1b : un jeton peut exister côté OpenBao sans être celui du
            # runbook (policy default rattachée, réponse tronquée). Il est révoqué
            # ici, root encore en main, et ne sort jamais du processus.
            accessor, token, created = _accessor_of(auth), None, None
            revoked = False
            if accessor is not None:
                try:
                    client.auth.token.revoke_accessor(accessor)
                    revoked = True
                except Exception:  # noqa: BLE001 ; échec publié dans le reçu, l'accessor permet de relancer
                    revoked = False
            raise BaoTokenUnconfirmed(accessor, revoked)
    finally:
        client.token = ""  # le root token ne survit pas à l'appel
    receipt = {"policy": name, "policy_sha256": hashlib.sha256(hcl.encode()).hexdigest(),
               "paths": hcl.count("path "), "accessor": auth.get("accessor"), "ttl_seconds": ttl_seconds}
    return token, receipt


def revoke_bao_accessor(*, nonce: str, accessor: str, settings=None, load_init_keys=None, environ=None) -> None:
    """Révoque le jeton du job par son accessor (reçu d'émission), avec le root du produit."""
    import re

    require_issuer(nonce, environ)
    if type(accessor) is not str or not re.fullmatch(ACCESSOR, accessor):
        raise ValueError("831 Bao accessor required")
    client = _root_client(_settings(settings), load_init_keys)
    try:
        client.auth.token.revoke_accessor(accessor)
    finally:
        client.token = ""


class PreparationJob:
    """Une autorité opérateur par processus ; les faits sont reconstruits à chaque lecture."""

    def __init__(self, *, nonce: str, bearer: str, bao_token: str):
        self.nonce, self._bearer, self._bao_token = nonce, bearer, bao_token

    async def open(self) -> None:
        import hvac

        from ..auth.policies import init_policy_store
        from ..auth.token_store import init_token_store
        from ..config import get_settings
        from ..openbao.manager import set_hvac_client

        settings = get_settings()
        if settings.metadata_backend != "postgres":
            raise RuntimeError("831 Vault PostgreSQL metadata required")
        # Stores PG : lecture des faits frais de chaque requête, pas d'un cache.
        init_token_store()
        init_policy_store()
        client = hvac.Client(url=settings.openbao_addr, token=self._bao_token)
        self._bao_token = ""
        # Pas de `is_authenticated()` : il appelle `auth/token/lookup-self`, que
        # seule la policy `default` accorde, et le jeton est créé sans elle. Un
        # jeton invalide échoue sur la lecture du secret PG app (`backend_denied`),
        # avant `opened` (revue finale P2).
        set_hvac_client(client)
        try:
            # Reçu réel : le secret PG app est lu avec CE jeton, puis la connexion
            # vérifie base, rôle, droits et schéma. Un jeton limité aux canaries
            # échoue ici, avant `opened`, donc avant tout lot Mission/Agent/Teleport.
            await asyncio.to_thread(self._probe_postgres)
        except BaseException:
            set_hvac_client(None)
            raise

    @staticmethod
    def _probe_postgres() -> None:
        from .postgres import connection

        with connection() as conn:
            conn.execute("SELECT 1")

    async def prepare_read(self, **arguments):
        from .fixture831_writer import preparation_fact, prepare_read

        return await prepare_read(preparation_fact(arguments, nonce=self.nonce), self._bearer)

    async def close(self) -> None:
        from ..openbao.manager import set_hvac_client

        set_hvac_client(None)
        self._bearer = ""


async def dispatch(job, action, arguments):
    if type(arguments) is not dict:
        raise ValueError("831 object arguments required")
    if action == "prepare_read":
        return await job.prepare_read(**arguments)
    if action == "close" and not arguments:
        return await job.close()
    raise ValueError("831 closed owner operation required")


def emit(writer, document):
    raw = json.dumps(document, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > LIMIT:
        raise ValueError("831 response exceeds bound; observe")
    writer.write(raw + b"\n")
    writer.flush()


async def serve(job, reader, writer):
    await job.open()
    emit(writer, {"seq": 0, "nonce": job.nonce, "opened": True})
    seq = 0
    while True:
        raw = await asyncio.to_thread(reader.readline, LIMIT + 1)
        if not raw:
            return 1  # EOF sans close n'est jamais un reçu de fermeture.
        seq += 1
        try:
            if len(raw) > LIMIT or not raw.endswith(b"\n"):
                raise ValueError("831 bounded line required")
            message = json.loads(raw)
            if (type(message) is not dict or set(message) != {"seq", "action", "arguments"}
                    or type(message["seq"]) is not int or message["seq"] != seq):
                raise ValueError("831 exact ordered owner command required")
            result = await dispatch(job, message["action"], message["arguments"])
            emit(writer, {"seq": seq, "result": result})
        except Exception:  # noqa: BLE001 ; protocole fermé, toute erreur devient owner_result_uncertain sans détail
            # Ni code, ni message, ni identifiant : la recette observe l'audit PG.
            emit(writer, {"seq": seq, "error": "owner_result_uncertain"})
            return 1
        if message["action"] == "close":
            return 0


def main(argv=None, *, stdin=None, stdout=None, issue=issue_bao_read_token, revoke=revoke_bao_accessor):
    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--bearer-file", type=Path)
    parser.add_argument("--stdin-credentials", action="store_true")
    parser.add_argument("--print-bao-policy", action="store_true")
    parser.add_argument("--issue-bao-read-token", action="store_true")
    parser.add_argument("--ttl-seconds", type=int)
    parser.add_argument("--revoke-bao-accessor")
    args = parser.parse_args(argv)
    import re

    if not re.fullmatch("[0-9a-f]{12}", args.nonce):
        raise ValueError("831 nonce required")
    reader = stdin if stdin is not None else sys.stdin.buffer
    writer = stdout if stdout is not None else sys.stdout.buffer
    if args.print_bao_policy:
        # Recette : HCL tiré des réglages du job (aucun secret lu ni affiché).
        from ..config import get_settings

        settings = get_settings()
        sys.stdout.write(bao_read_policy(nonce=args.nonce, pg_mount=settings.metadata_pg_vault_id,
                                         pg_path=settings.metadata_pg_secret_path))
        return 0
    if args.revoke_bao_accessor is not None:
        if args.bearer_file is not None or args.stdin_credentials or args.issue_bao_read_token \
                or args.ttl_seconds is not None:
            raise ValueError("831 Bao accessor revocation takes only the accessor")
        with redirect_stdout(sys.stderr):
            try:
                revoke(nonce=args.nonce, accessor=args.revoke_bao_accessor)
            except IssuerNotArmed:
                sys.stderr.write(json.dumps({"status": "refused", "code": "bao_issuer_not_armed"}) + "\n")
                return 2
            except Exception:  # noqa: BLE001 ; refus publié sans message serveur, l'opérateur relance
                sys.stderr.write(json.dumps({"status": "refused", "code": "bao_revoke_unconfirmed"}) + "\n")
                return 1
            sys.stderr.write(json.dumps({"status": "revoked", "accessor": args.revoke_bao_accessor}) + "\n")
        return 0
    if args.issue_bao_read_token:
        if args.bearer_file is not None or args.stdin_credentials or args.ttl_seconds is None:
            raise ValueError("831 Bao token issue takes only --ttl-seconds")
        with redirect_stdout(sys.stderr):
            try:
                token, receipt = issue(nonce=args.nonce, ttl_seconds=args.ttl_seconds)
            except IssuerNotArmed:
                sys.stderr.write(json.dumps({"status": "refused", "code": "bao_issuer_not_armed"}) + "\n")
                return 2
            except BaoTokenUnconfirmed as error:
                sys.stderr.write(json.dumps({"status": "refused", "code": "bao_token_unconfirmed",
                                             "accessor": error.accessor, "revoked": error.revoked}) + "\n")
                return 1
            except Exception:  # noqa: BLE001 ; aucun jeton connu, refus publié sans message serveur
                sys.stderr.write(json.dumps({"status": "refused", "code": "bao_token_unconfirmed",
                                             "accessor": None, "revoked": False}) + "\n")
                return 1
            # Reçu d'abord (accessor pour révoquer si la suite échoue), puis le jeton seul.
            sys.stderr.write(json.dumps({"status": "created", **receipt}) + "\n")
            sys.stderr.flush()
        writer.write(token.encode("ascii") + b"\n")
        writer.flush()
        return 0
    if args.stdin_credentials:
        if args.bearer_file is not None or os.environ.get("Q831_BAO_READ_FILE"):
            raise ValueError("831 one credential source required")
        bearer, bao_token = read_stdin_credential(reader), read_stdin_credential(reader)
    else:
        if args.bearer_file is None:
            raise ValueError("831 bearer file required")
        bao_file = os.environ.get("Q831_BAO_READ_FILE", "")
        if not bao_file or not os.path.isabs(bao_file):
            raise ValueError("831 Bao read file required")
        bearer, bao_token = read_private(args.bearer_file), read_private(Path(bao_file))
    with redirect_stdout(sys.stderr):
        job = PreparationJob(nonce=args.nonce, bearer=bearer, bao_token=bao_token)
        del bearer, bao_token
        try:
            return asyncio.run(serve(job, reader, writer))
        except Exception:  # noqa: BLE001 ; ouverture non confirmée, aucun détail ne sort du job
            emit(writer, {"seq": 0, "error": "owner_open_unconfirmed"})
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
