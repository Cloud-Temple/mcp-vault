"""Jeton OpenBao du job Vault831 : policy exacte et reçu d'ouverture réel (revue R3, P2).

OpenBao est simulé au niveau HTTP : il applique la policy HCL comme le ferait
le serveur (chemins exacts, lecture seule, 403 hors policy). Le jeton du runbook
est créé en `-no-default-policy` : `auth/token/lookup-self` n'est donc pas dans
sa policy et OpenBao le refuse. Le vrai `hvac.Client` est utilisé, branché sur
un adaptateur `requests` qui applique la même policy que le transport httpx des
lectures `credentials()` / `exact_kv`.
PostgreSQL n'est pas joint : `psycopg.connect` enregistre les paramètres reçus et
s'arrête là, ce qui prouve que la policy a laissé lire le secret PG app.
"""
from __future__ import annotations

import asyncio
import json
import re
from types import SimpleNamespace
from typing import ClassVar

import httpx
import pytest
import requests
from requests.adapters import BaseAdapter

from mcp_vault.storage import fixture831_job as job_module

NONCE = "0123456789ab"
PG_MOUNT, PG_PATH = "vault-metadata", "sql/app"
PG_SECRET = {"host": "pg.test", "port": "5432", "dbname": "vault831", "user": "vault_app",
             "password": "pg-app-password-synthetic"}


ROOT_TOKEN = "root-token-synthetic"


class PgReached(Exception):
    pass


def canaries_only(nonce=NONCE):
    """Policy du round 3 : canaries seules. Elle doit échouer à l'ouverture."""
    return "".join(f'path "q831-{nonce}-t{slot:02d}/data/q831/{nonce}/canary" {{\n  capabilities = ["read"]\n}}\n'
                   for slot in range(20))


def allowed(hcl):
    stanzas = re.findall(r'path "([^"]+)" \{\n  capabilities = \["read"\]\n\}\n', hcl)
    assert "".join(f'path "{p}" {{\n  capabilities = ["read"]\n}}\n' for p in stanzas) == hcl
    return set(stanzas)


@pytest.fixture
def fake_bao(monkeypatch):
    import hvac
    import psycopg

    from mcp_vault import config
    from mcp_vault.auth import policies, token_store
    from mcp_vault.openbao import manager
    from mcp_vault.storage import postgres, reader

    cfg = config.Settings(_env_file=None).model_copy(update={
        "metadata_backend": "postgres", "metadata_pg_vault_id": PG_MOUNT, "metadata_pg_secret_path": PG_PATH,
        "metadata_pg_database": "vault831", "metadata_pg_app_role": "vault_app",
        "openbao_addr": "http://bao.test:8200"})
    for module in (config, postgres, reader):
        monkeypatch.setattr(module, "get_settings", lambda: cfg)
    monkeypatch.setattr(token_store, "init_token_store", lambda: None)
    monkeypatch.setattr(policies, "init_policy_store", lambda: None)
    # Garde d'émission : posée sur le seul service vault831-<nonce> (revue P3-B1a).
    monkeypatch.setenv(job_module.ISSUER_ENV, NONCE)
    state = SimpleNamespace(policy=set(), http=[], connect=[], acl={}, created=[], cfg=cfg, revoked=[],
                            revoke_fail=False, attach_default=False)
    secrets = {f"{PG_MOUNT}/data/{PG_PATH}": PG_SECRET,
               f"{PG_MOUNT}/data/sql/provisioner": dict(PG_SECRET, user="vault_prov")}
    for slot in range(20):
        secrets[f"q831-{NONCE}-t{slot:02d}/data/q831/{NONCE}/canary"] = {"fixture831": f"canary-{slot}"}

    def decide(method, path, token, body=None):
        # Même règle qu'OpenBao : jeton inconnu ou chemin hors policy = 403.
        state.http.append(path)
        if token == ROOT_TOKEN:
            return root_decide(method, path, body)
        if token != "bao-job-token" or path not in state.policy or method != "GET":
            return 403, {"errors": ["permission denied"]}
        return 200, {"data": {"data": secrets[path], "metadata": {"version": 1}}}

    def root_decide(method, path, body):
        name = path.removeprefix("sys/policy/")
        if path.startswith("sys/policy/") and method == "GET":
            if name not in state.acl:
                return 404, {"errors": []}
            return 200, {"name": name, "rules": state.acl[name], "data": {"name": name, "rules": state.acl[name]}}
        if path.startswith("sys/policy/") and method == "PUT":
            state.acl[name] = body["policy"]
            return 204, None
        if path == "auth/token/create-orphan" and method == "POST":
            state.created.append(body)
            default = state.attach_default or not body.get("no_default_policy")
            policies = sorted(body["policies"] + (["default"] if default else []))
            return 200, {"auth": {"client_token": "bao-job-token", "accessor": "acc-831",
                                  "policies": policies, "renewable": body.get("renewable")}}
        if path == "auth/token/revoke-accessor" and method == "POST":
            if state.revoke_fail or body.get("accessor") != ("acc-831" if state.created else None):
                return 400, {"errors": ["invalid accessor"]}
            state.revoked.append(body["accessor"])
            return 204, None
        return 403, {"errors": ["permission denied"]}

    def handler(request):
        status, body = decide(request.method, request.url.path.removeprefix("/v1/"),
                              request.headers.get("X-Vault-Token"))
        return httpx.Response(status, json=body)

    real_client = httpx.Client

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client)

    class PolicyAdapter(BaseAdapter):
        """Transport `requests` du vrai hvac, soumis à la même policy."""

        def send(self, request, **_):
            sent = json.loads(request.body) if request.body else None
            status, body = decide(request.method, request.path_url.split("?")[0].removeprefix("/v1/"),
                                  request.headers.get("X-Vault-Token"), sent)
            response = requests.Response()
            response.status_code = status
            response._content = b"" if body is None else json.dumps(body).encode()
            response.headers["Content-Type"] = "application/json"
            response.url, response.request = request.url, request
            return response

        def close(self):
            pass

    real_hvac = hvac.Client

    def hvac_client(url, token):
        assert url == cfg.openbao_addr
        session = requests.Session()
        session.mount("http://", PolicyAdapter())
        return real_hvac(url=url, token=token, session=session)

    monkeypatch.setattr(hvac, "Client", hvac_client)
    state.real_hvac = hvac_client

    def connect(**kwargs):
        state.connect.append({k: kwargs[k] for k in ("user", "password", "dbname")})
        raise PgReached()

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(manager, "_client", None)
    yield state
    manager.set_hvac_client(None)


def job():
    return job_module.PreparationJob(nonce=NONCE, bearer="q831-operator", bao_token="bao-job-token")


def test_policy_exacte_un_chemin_pg_app_et_vingt_canaries():
    hcl = job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH)
    paths = allowed(hcl)
    assert len(paths) == 21 and f"{PG_MOUNT}/data/{PG_PATH}" in paths
    assert {p for p in paths if "canary" in p} == {
        f"q831-{NONCE}-t{slot:02d}/data/q831/{NONCE}/canary" for slot in range(20)}
    assert not any("*" in p or "+" in p for p in paths)
    for bad in [{"nonce": "XYZ"}, {"pg_mount": "../x"}, {"pg_path": "sql/*"}]:
        with pytest.raises(ValueError):
            job_module.bao_read_policy(**{"nonce": NONCE, "pg_mount": PG_MOUNT, "pg_path": PG_PATH, **bad})


def test_jeton_limite_aux_canaries_echoue_a_louverture(fake_bao):
    from mcp_vault.openbao import manager
    from mcp_vault.storage.postgres import MetadataUnavailable

    fake_bao.policy = allowed(canaries_only())
    with pytest.raises(MetadataUnavailable, match="backend_denied"):
        asyncio.run(job().open())
    # Refus OpenBao sur le secret PG app, aucune connexion tentée, client retiré.
    assert fake_bao.http == [f"{PG_MOUNT}/data/{PG_PATH}"] and fake_bao.connect == []
    assert manager.get_hvac_client() is None


def test_jeton_de_la_policy_versionnee_lit_pg_app_puis_se_connecte(fake_bao):
    from mcp_vault.openbao import manager
    from mcp_vault.storage.postgres import MetadataUnavailable

    fake_bao.policy = allowed(job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH))
    with pytest.raises(MetadataUnavailable, match="storage_unavailable") as error:
        asyncio.run(job().open())
    assert type(error.value.__cause__) is PgReached
    assert fake_bao.connect == [{"user": "vault_app", "password": PG_SECRET["password"], "dbname": "vault831"}]
    # Échec PG = pas de reçu : le client Bao n'est pas laissé installé.
    assert manager.get_hvac_client() is None


def test_ouverture_confirmee_seulement_apres_la_sonde_pg(fake_bao, monkeypatch):
    from mcp_vault.openbao import manager

    fake_bao.policy = allowed(job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH))
    probes = []

    def probe():
        from mcp_vault.storage.postgres import credentials

        probes.append(credentials()["user"])

    monkeypatch.setattr(job_module.PreparationJob, "_probe_postgres", staticmethod(probe))
    asyncio.run(job().open())
    assert probes == ["vault_app"] and manager.get_hvac_client() is not None


def test_policy_versionnee_refuse_provisionneur_autre_tenant_et_autre_nonce(fake_bao):
    from mcp_vault.openbao import manager
    from mcp_vault.storage.postgres import MetadataUnavailable, credentials
    from mcp_vault.storage.reader import exact_kv

    fake_bao.policy = allowed(job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH))
    manager.set_hvac_client(__import__("hvac").Client(url="http://bao.test:8200", token="bao-job-token"))
    assert credentials()["user"] == "vault_app"
    for mount, path in [(PG_MOUNT, "sql/provisioner"), (PG_MOUNT, "sql/audit-maintenance"),
                        (f"q831-{NONCE}-t20", f"q831/{NONCE}/canary"),
                        ("q831-ba9876543210-t00", "q831/ba9876543210/canary")]:
        with pytest.raises(MetadataUnavailable, match="backend_denied"):
            exact_kv(mount, path)


def test_jeton_bao_invalide_refuse_par_la_lecture_pg_avant_opened(fake_bao):
    from mcp_vault.openbao import manager
    from mcp_vault.storage.postgres import MetadataUnavailable

    fake_bao.policy = allowed(job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH))
    bad = job_module.PreparationJob(nonce=NONCE, bearer="q831-operator", bao_token="autre")
    with pytest.raises(MetadataUnavailable, match="backend_denied"):
        asyncio.run(bad.open())
    # Une seule requête, la lecture du secret PG app, refusée : ni connexion ni client laissé.
    assert fake_bao.http == [f"{PG_MOUNT}/data/{PG_PATH}"] and fake_bao.connect == []
    assert manager.get_hvac_client() is None


def test_jeton_sans_policy_default_ouvre_le_job_sans_lookup_self(fake_bao, monkeypatch):
    """Revue finale P2 : le jeton du runbook (-no-default-policy) n'a pas lookup-self."""
    from mcp_vault.openbao import manager

    fake_bao.policy = allowed(job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH))
    # Le faux OpenBao rejoue bien le refus : le vrai hvac conclut « non authentifié ».
    assert fake_bao.real_hvac("http://bao.test:8200", "bao-job-token").is_authenticated() is False
    assert fake_bao.http == ["auth/token/lookup-self"]
    fake_bao.http.clear()
    probes = []

    def probe():
        from mcp_vault.storage.postgres import credentials

        probes.append(credentials()["user"])

    monkeypatch.setattr(job_module.PreparationJob, "_probe_postgres", staticmethod(probe))
    asyncio.run(job().open())
    # L'ouverture ne dépend que de la lecture PG app autorisée par la policy exacte.
    assert probes == ["vault_app"] and fake_bao.http == [f"{PG_MOUNT}/data/{PG_PATH}"]
    assert manager.get_hvac_client() is not None


def test_impression_de_la_policy_sans_secret(monkeypatch, capsys):
    from mcp_vault import config

    cfg = config.Settings(_env_file=None).model_copy(update={
        "metadata_pg_vault_id": PG_MOUNT, "metadata_pg_secret_path": PG_PATH})
    monkeypatch.setattr(config, "get_settings", lambda: cfg)
    assert job_module.main(["--nonce", NONCE, "--print-bao-policy"]) == 0
    assert capsys.readouterr().out == job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH)


# -- Émission du jeton OpenBao du job (point 3 du plan de composition W1) --------------------

def issue(fake_bao, **change):
    arguments = {"nonce": NONCE, "ttl_seconds": 604800, "settings": fake_bao.cfg,
                 "load_init_keys": lambda: {"keys": ["k"], "root_token": ROOT_TOKEN}}
    arguments.update(change)
    return job_module.issue_bao_read_token(**arguments)


def test_emission_policy_exacte_puis_jeton_qui_ouvre_le_job(fake_bao, monkeypatch):
    from mcp_vault.openbao import manager

    token, receipt = issue(fake_bao)
    name = f"q831-{NONCE}-vault-read"
    hcl = job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH)
    assert fake_bao.acl == {name: hcl}
    (sent,) = fake_bao.created
    assert sent == {"policies": [name], "no_default_policy": True, "renewable": False, "ttl": "604800s",
                    "explicit_max_ttl": "604800s", "display_name": name, "num_uses": 0}
    assert token == "bao-job-token" and receipt["paths"] == 21 and receipt["accessor"] == "acc-831"
    assert ROOT_TOKEN not in json.dumps(receipt)
    # Le jeton émis, sous la seule policy écrite (sans default), ouvre réellement le job.
    fake_bao.policy = allowed(fake_bao.acl[name])
    fake_bao.http.clear()
    monkeypatch.setattr(job_module.PreparationJob, "_probe_postgres",
                        staticmethod(lambda: __import__("mcp_vault.storage.postgres").storage.postgres.credentials()))
    asyncio.run(job_module.PreparationJob(nonce=NONCE, bearer="q831-operator", bao_token=token).open())
    assert fake_bao.http == [f"{PG_MOUNT}/data/{PG_PATH}"] and manager.get_hvac_client() is not None


def test_policy_existante_identique_reutilisee_sans_reecriture(fake_bao):
    name = f"q831-{NONCE}-vault-read"
    fake_bao.acl[name] = job_module.bao_read_policy(nonce=NONCE, pg_mount=PG_MOUNT, pg_path=PG_PATH)
    issue(fake_bao)
    assert f"sys/policy/{name}" in fake_bao.http and len(fake_bao.created) == 1
    assert [p for p in fake_bao.http if p.startswith("sys/policy/")] == [f"sys/policy/{name}"]  # lecture seule


def test_policy_existante_elargie_refusee_avant_tout_jeton(fake_bao):
    name = f"q831-{NONCE}-vault-read"
    fake_bao.acl[name] = 'path "*" {\n  capabilities = ["read"]\n}\n'
    with pytest.raises(RuntimeError, match="differs"):
        issue(fake_bao)
    assert fake_bao.created == [] and fake_bao.acl[name].startswith('path "*"')


@pytest.mark.parametrize("change,error", [
    ({"ttl_seconds": 3599}, ValueError), ({"ttl_seconds": 90 * 86400 + 1}, ValueError),
    ({"ttl_seconds": "604800"}, ValueError), ({"load_init_keys": lambda: None}, RuntimeError),
    ({"load_init_keys": lambda: {"keys": []}}, RuntimeError)],
    ids=["ttl-court", "ttl-long", "ttl-texte", "cles-absentes", "root-absent"])
def test_emission_refusee_sans_ecriture(fake_bao, change, error):
    with pytest.raises(error):
        issue(fake_bao, **change)
    assert fake_bao.acl == {} and fake_bao.created == []


def test_jeton_cree_avec_policy_default_refuse(fake_bao, monkeypatch):
    """Si OpenBao rattache quand même `default`, le jeton n'est pas celui du runbook."""
    original = job_module.issue_bao_read_token

    def with_default(**kwargs):
        import hvac

        real = hvac.Client

        def client(url, token):
            c = real(url, token)
            create = c.auth.token.create_orphan

            def create_orphan(**params):
                params["no_default_policy"] = False
                return create(**params)

            c.auth.token.create_orphan = create_orphan
            return c

        monkeypatch.setattr(hvac, "Client", client)
        return original(**kwargs)

    with pytest.raises(RuntimeError, match="unconfirmed") as raised:
        with_default(nonce=NONCE, ttl_seconds=604800, settings=fake_bao.cfg,
                     load_init_keys=lambda: {"root_token": ROOT_TOKEN})
    # Revue P3-B1b : le jeton créé mais non conforme est révoqué par son accessor.
    assert fake_bao.revoked == ["acc-831"] and raised.value.revoked is True


def test_main_emission_jeton_seul_sur_stdout(fake_bao, capsys):
    import io

    out = io.BytesIO()
    code = job_module.main(["--nonce", NONCE, "--issue-bao-read-token", "--ttl-seconds", "604800"], stdout=out,
                           issue=lambda **kw: issue(fake_bao, **kw))
    assert code == 0 and out.getvalue() == b"bao-job-token\n"
    receipt = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert receipt["status"] == "created" and receipt["policy"] == f"q831-{NONCE}-vault-read"
    assert "bao-job-token" not in json.dumps(receipt) and ROOT_TOKEN not in json.dumps(receipt)


def test_main_emission_refusee_rien_sur_stdout(fake_bao, capsys):
    import io

    out = io.BytesIO()

    def refuse(**kwargs):
        raise RuntimeError("831 existing Bao policy differs")

    code = job_module.main(["--nonce", NONCE, "--issue-bao-read-token", "--ttl-seconds", "604800"], stdout=out,
                           issue=refuse)
    assert code == 1 and out.getvalue() == b""
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["status"] == "refused"
    with pytest.raises(ValueError):
        job_module.main(["--nonce", NONCE, "--issue-bao-read-token"], stdout=out, issue=refuse)


# -- Credentials par stdin (lancement dans le conteneur, point 2) ----------------------------

class Recorder:
    seen: ClassVar[list] = []

    def __init__(self, *, nonce, bearer, bao_token):
        self.nonce = nonce
        Recorder.seen.append((bearer, bao_token))

    async def open(self):
        pass

    async def close(self):
        pass


def test_credentials_par_stdin_puis_protocole(monkeypatch):
    import io

    Recorder.seen = []
    monkeypatch.setattr(job_module, "PreparationJob", Recorder)
    monkeypatch.delenv("Q831_BAO_READ_FILE", raising=False)
    stdin = io.BytesIO(b"q831-operator-bearer\nbao-job-token\n" + b'{"seq":1,"action":"close","arguments":{}}\n')
    out = io.BytesIO()
    assert job_module.main(["--nonce", NONCE, "--stdin-credentials"], stdin=stdin, stdout=out) == 0
    assert Recorder.seen == [("q831-operator-bearer", "bao-job-token")]
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert lines == [{"seq": 0, "nonce": NONCE, "opened": True}, {"seq": 1, "result": None}]
    assert b"bearer" not in out.getvalue() and b"bao-job-token" not in out.getvalue()


@pytest.mark.parametrize("argv,stdin,env", [
    (["--stdin-credentials", "--bearer-file", "/tmp/x"], b"a\nb\n", None),
    (["--stdin-credentials"], b"a\nb\n", "/tmp/bao"),
    (["--stdin-credentials"], b"seulement-un\n", None),
    (["--stdin-credentials"], b"\nb\n", None),
    (["--stdin-credentials"], b"avec espace\nb\n", None),
    (["--stdin-credentials"], b"x" * 8193 + b"\nb\n", None),
], ids=["deux-sources-fichier", "deux-sources-env", "une-ligne", "vide", "espace", "trop-long"])
def test_credentials_par_stdin_refuses_avant_ouverture(monkeypatch, argv, stdin, env):
    import io

    Recorder.seen = []
    monkeypatch.setattr(job_module, "PreparationJob", Recorder)
    if env:
        monkeypatch.setenv("Q831_BAO_READ_FILE", env)
    else:
        monkeypatch.delenv("Q831_BAO_READ_FILE", raising=False)
    out = io.BytesIO()
    with pytest.raises(ValueError):
        job_module.main(["--nonce", NONCE, *argv], stdin=io.BytesIO(stdin), stdout=out)
    assert Recorder.seen == [] and out.getvalue() == b""


# -- Garde d'émission et révocation par accessor (revue P3-B1a, B1b, B1c) ------------------

def no_keys():
    raise AssertionError("aucune clé ne doit être chargée sans la garde d'émission")


@pytest.mark.parametrize("value", [None, "", "ba9876543210"], ids=["absente", "vide", "autre-nonce"])
def test_garde_emission_refuse_avant_toute_cle(fake_bao, monkeypatch, value):
    if value is None:
        monkeypatch.delenv(job_module.ISSUER_ENV)
    else:
        monkeypatch.setenv(job_module.ISSUER_ENV, value)
    with pytest.raises(job_module.IssuerNotArmed):
        issue(fake_bao, load_init_keys=no_keys)
    with pytest.raises(job_module.IssuerNotArmed):
        job_module.revoke_bao_accessor(nonce=NONCE, accessor="acc-831", settings=fake_bao.cfg,
                                       load_init_keys=no_keys)
    assert fake_bao.http == [] and fake_bao.acl == {} and fake_bao.created == []


def test_main_garde_emission_code_2_sans_jeton(fake_bao, monkeypatch, capsys):
    import io

    monkeypatch.delenv(job_module.ISSUER_ENV)
    out = io.BytesIO()
    code = job_module.main(["--nonce", NONCE, "--issue-bao-read-token", "--ttl-seconds", "604800"], stdout=out,
                           issue=lambda **kw: issue(fake_bao, load_init_keys=no_keys, **kw))
    assert code == 2 and out.getvalue() == b"" and fake_bao.http == []
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1]) == {
        "status": "refused", "code": "bao_issuer_not_armed"}


@pytest.mark.parametrize("revoke_fail", [False, True], ids=["revoque", "revocation-echouee"])
def test_jeton_non_conforme_revoque_accessor_dans_le_recu(fake_bao, capsys, revoke_fail):
    import io

    fake_bao.attach_default, fake_bao.revoke_fail = True, revoke_fail
    out = io.BytesIO()
    code = job_module.main(["--nonce", NONCE, "--issue-bao-read-token", "--ttl-seconds", "604800"], stdout=out,
                           issue=lambda **kw: issue(fake_bao, **kw))
    receipt = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert code == 1 and out.getvalue() == b""
    assert receipt == {"status": "refused", "code": "bao_token_unconfirmed", "accessor": "acc-831",
                       "revoked": not revoke_fail}
    assert fake_bao.revoked == ([] if revoke_fail else ["acc-831"])
    assert "auth/token/revoke-accessor" in fake_bao.http and "bao-job-token" not in json.dumps(receipt)


def test_reponse_sans_accessor_rien_a_revoquer(fake_bao, monkeypatch):
    import hvac

    real = hvac.Client

    def client(url, token):
        c = real(url, token)
        c.auth.token.create_orphan = lambda **params: {"auth": {"client_token": "bao-job-token", "policies": []}}
        return c

    monkeypatch.setattr(hvac, "Client", client)
    with pytest.raises(job_module.BaoTokenUnconfirmed) as raised:
        issue(fake_bao)
    assert (raised.value.accessor, raised.value.revoked) == (None, False)
    assert "auth/token/revoke-accessor" not in fake_bao.http


def test_sous_commande_revocation_par_accessor(fake_bao, capsys):
    issue(fake_bao)  # le faux OpenBao ne connaît l'accessor qu'après une émission
    fake_bao.http.clear()

    def revoke(**kw):
        return job_module.revoke_bao_accessor(settings=fake_bao.cfg, load_init_keys=lambda: {"root_token": ROOT_TOKEN},
                                              **kw)

    assert job_module.main(["--nonce", NONCE, "--revoke-bao-accessor", "acc-831"], revoke=revoke) == 0
    assert fake_bao.revoked == ["acc-831"] and fake_bao.http == ["auth/token/revoke-accessor"]
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1]) == {"status": "revoked",
                                                                          "accessor": "acc-831"}
    # Accessor inconnu d'OpenBao : refus publié, sans message serveur.
    assert job_module.main(["--nonce", NONCE, "--revoke-bao-accessor", "acc-autre"], revoke=revoke) == 1
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "bao_revoke_unconfirmed"
    for argv in (["--revoke-bao-accessor", "acc-831", "--issue-bao-read-token"],
                 ["--revoke-bao-accessor", "acc-831", "--ttl-seconds", "3600"],
                 ["--revoke-bao-accessor", "acc-831", "--stdin-credentials"]):
        with pytest.raises(ValueError):
            job_module.main(["--nonce", NONCE, *argv], revoke=revoke)
    with pytest.raises(ValueError):
        job_module.revoke_bao_accessor(nonce=NONCE, accessor="acc 831", settings=fake_bao.cfg,
                                       load_init_keys=lambda: {"root_token": ROOT_TOKEN})
