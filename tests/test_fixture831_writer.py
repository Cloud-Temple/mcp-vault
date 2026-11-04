"""Writer A2 de la préparation831 (plan831 R1 A2) et son job privé.

PG est une connexion en mémoire qui répond aux requêtes réelles de
`load_facts`, de la revalidation sous verrou et du writer d'audit, et garde
les lignes écrites. OpenBao est substitué au seul appel
`read_secret_version`. Le chemin produit (`_write`, `record_step`,
`read_secret`, `bao_step`, `check_*`, validateur du middleware) est réel.
"""

import asyncio
import hashlib
import io
import json
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from mcp_vault.storage import admission, audit_pg, postgres
from mcp_vault.storage import fixture831_job as job_module
from mcp_vault.storage import fixture831_writer as writer
from mcp_vault.storage.fixture831_preparation import (
    PREPARATION_TOOL,
    PreparationAuditScope,
)
from mcp_vault.storage.hub_vault_activity import MissionAuditScope

NONCE = "0123456789ab"
TENANT = f"q831-{NONCE}-tenant07"
VAULT = f"q831-{NONCE}-t07"
PATH = f"q831/{NONCE}/canary"
MISSION = "mis_0123abcd"
CANARY = "public-synthetic-canary-07"
RAW = "q831-operator-vault-token"
TOKEN_HASH = hashlib.sha256(RAW.encode()).hexdigest()


def arguments(**change):
    base = dict(mission_id=MISSION, tenant_id=TENANT, operation_id=f"q831-prepare-{MISSION}",
                vault_id=VAULT, path=PATH, expected_sha256=hashlib.sha256(CANARY.encode()).hexdigest())
    base.update(change)
    return base


@pytest.fixture
def bench(monkeypatch):
    from mcp_vault import config
    from mcp_vault.auth import middleware, policies
    from mcp_vault.storage import stores
    from mcp_vault.vault import secrets

    cfg = config.Settings(_env_file=None).model_copy(update=dict(
        metadata_backend="postgres", metadata_instance_id="vault831", mcp_auth_mode="bearer"))
    for module in (config, middleware, admission, postgres, audit_pg, stores):
        monkeypatch.setattr(module, "get_settings", lambda: cfg)
    now = datetime.now(timezone.utc).isoformat()
    state = dict(
        token=dict(hash=TOKEN_HASH, client_name="q831-vault-operator", permissions=["read"],
                   allowed_resources=[VAULT], policy_id="q831-prepare", revoked=False, expires_at=None),
        token_revision=1,
        policy=dict(policy_id="q831-prepare", allowed_tools=["secret_read"], denied_tools=[],
                    path_rules=[dict(vault_pattern=f"q831-{NONCE}-t*", permissions=["read"],
                                     allowed_paths=[f"q831/{NONCE}/*"])]),
        policy_revision=1,
        binding=dict(tenant_id=TENANT, instance_id="vault831", allowed_resources=[VAULT], permissions=["read"],
                     enabled=True, policy_id="q831-prepare", expires_at=None, created_at=now, updated_at=now),
        binding_revision=1,
        on_lock=None, fail_commit_on=None, bao=CANARY, bao_error=None,
    )
    db = dict(calls=[], events=[], connections=0)
    bao_reads = []

    class Conn:
        def __init__(self):
            self.end = time.monotonic() + 30
            self.pending_calls, self.pending_events = [], []
            self.handler = None

        def add_notice_handler(self, handler):
            self.handler = handler

        def execute(self, sql, params=None):
            values = []
            if sql == "COMMIT":
                kinds = {e["phase"] for e in self.pending_events}
                if state["fail_commit_on"] in kinds:
                    raise OSError("PRIVATE-CANARY commit transport")
                db["calls"] += self.pending_calls
                db["events"] += self.pending_events
            elif sql == "ROLLBACK":
                self.pending_calls, self.pending_events = [], []
            elif "FOR SHARE" in sql and state["on_lock"]:
                action, state["on_lock"] = state["on_lock"], None
                action()
            if sql.startswith("INSERT INTO vault_metadata.audit_calls"):
                keys = ("instance_id", "call_id", "actor_ref", "tool", "vault_id", "tenant_id", "mission_id",
                        "operation_id")
                self.pending_calls.append(dict(zip(keys, params)))
            elif sql.startswith("INSERT INTO vault_metadata.audit_events"):
                keys = ("instance_id", "call_id", "phase", "step_id", "mutation_id", "outcome", "duration_ms")
                self.pending_events.append(dict(zip(keys, params)))
            elif "FROM vault_metadata.audit_events" in sql:
                values = []
            elif "vault_metadata.tokens" in sql:
                hit = params[1] == TOKEN_HASH
                values = [dict(payload=state["token"], revision=state["token_revision"])] if hit else []
            elif "vault_metadata.mission_bindings" in sql:
                hit = params[1] == TENANT
                values = [dict(payload=state["binding"], revision=state["binding_revision"])] if hit else []
            elif "vault_metadata.policies" in sql:
                values = [dict(payload=state["policy"], revision=state["policy_revision"])]
            return SimpleNamespace(fetchall=lambda: values, fetchone=lambda: values[0] if values else None)

    @contextmanager
    def connected(**_kwargs):
        db["connections"] += 1
        yield Conn()

    for module in (admission, postgres, audit_pg):
        monkeypatch.setattr(module, "connection", connected)
    monkeypatch.setattr(audit_pg, "validate_durability", lambda conn: None)
    # Validateur opaque existant sur la vue admise, comme le fait le test842.
    monkeypatch.setattr(middleware, "get_token_store", lambda: postgres.request_facts.get()["token"])
    monkeypatch.setattr(policies, "get_policy_store", lambda: postgres.request_facts.get()["policy"])

    class KV:
        def read_secret_version(self, **kwargs):
            bao_reads.append(kwargs)
            if state["bao_error"]:
                raise state["bao_error"]
            return {"data": {"data": {"fixture831": state["bao"]}, "metadata": {"version": 3}}}

    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=KV())))
    monkeypatch.setattr(secrets, "get_hvac_client", lambda: client)
    return SimpleNamespace(state=state, db=db, bao_reads=bao_reads, cfg=cfg)


def fact(**change):
    return writer.preparation_fact(arguments(**change), nonce=NONCE)


def phases(db):
    return [(e["phase"], e["outcome"]) for e in db["events"]]


async def test_lecture_bao_reelle_puis_trois_evenements_operator(bench):
    result = await writer.prepare_read(fact(), RAW)
    assert result == {"call_id": bench.db["calls"][0]["call_id"], "vault_id": VAULT, "path": PATH,
                      "fixture_sha256": hashlib.sha256(CANARY.encode()).hexdigest(), "events": 3,
                      "outcome": "completed"}
    assert CANARY not in json.dumps(result)
    assert bench.bao_reads == [{"path": PATH, "mount_point": VAULT}]
    [call] = bench.db["calls"]
    assert call["actor_ref"] == writer.operator_actor(TOKEN_HASH, fact())
    assert call["actor_ref"].startswith("operator_") and len(call["actor_ref"]) == 25
    assert (call["tool"], call["vault_id"], call["tenant_id"], call["mission_id"], call["operation_id"]) == (
        PREPARATION_TOOL, VAULT, TENANT, MISSION, f"q831-prepare-{MISSION}")
    assert phases(bench.db) == [("admission", "admitted"), ("bao_step_outcome", "confirmed"),
                                ("public_terminal", "completed")]
    assert {e["call_id"] for e in bench.db["events"]} == {call["call_id"]}
    # La trace écrite est exactement celle que lit le périmètre de préparation du Hub.
    row = dict(call, instance_id="vault831")
    args = ("vault831", frozenset({VAULT}), TENANT, MISSION)
    assert PreparationAuditScope(*args).permits(row) and not MissionAuditScope(*args).permits(row)


@pytest.mark.parametrize("change", [
    dict(operation_id="q831-prepare-mis_99999999"), dict(tenant_id="autre-tenant"),
    dict(vault_id="q831-0123456789ab-admin"), dict(vault_id="q831-ffffffffffff-t07"),
    dict(path="q831/0123456789ab/autre"), dict(mission_id="mis_XYZ"), dict(expected_sha256="0" * 63),
])
def test_fait_hors_domaine_refuse(change):
    with pytest.raises(writer.PreparationRefused, match="fact_invalid"):
        fact(**change)


def test_fait_aux_champs_ouverts_refuse():
    with pytest.raises(writer.PreparationRefused, match="fact_invalid"):
        writer.preparation_fact(dict(arguments(), granted=True), nonce=NONCE)


async def test_fait_forge_ou_perime_refuse_avant_toute_base(bench):
    forged = writer.PreparationFact(*list(fact().__dict__.values())[:-1], object())
    with pytest.raises(writer.PreparationRefused, match="fact_invalid"):
        await writer.prepare_read(forged, RAW)
    stale = writer.preparation_fact(arguments(), nonce=NONCE, clock=lambda: time.monotonic() - 61)
    with pytest.raises(writer.PreparationRefused, match="fact_expired"):
        await writer.prepare_read(stale, RAW)
    assert bench.db["connections"] == 0 and bench.bao_reads == []


@pytest.mark.parametrize("change", ["admin", "foreign_resource", "unknown", "bootstrap", "revoked"])
async def test_jeton_operateur_non_conforme_refuse_sans_effet(bench, change):
    raw = RAW
    if change == "admin":
        bench.state["token"]["permissions"] = ["admin", "read"]
    elif change == "foreign_resource":
        bench.state["token"]["allowed_resources"] = [f"q831-{NONCE}-t08"]
    elif change == "unknown":
        raw = "jeton-inconnu"
    elif change == "bootstrap":
        raw = bench.cfg.admin_bootstrap_key
    elif change == "revoked":
        bench.state["token"]["revoked"] = True
    with pytest.raises(writer.PreparationRefused):
        await writer.prepare_read(fact(), raw)
    assert bench.db["calls"] == [] and bench.db["events"] == [] and bench.bao_reads == []


@pytest.mark.parametrize("change", ["absent", "disabled", "scope"])
async def test_binding_du_tenant_requis_avant_effet(bench, change):
    target = fact()
    if change == "absent":
        # La base ne rend aucun binding pour ce tenant.
        target = fact(tenant_id=f"q831-{NONCE}-tenant99")
    elif change == "disabled":
        bench.state["binding"]["enabled"] = False
    else:
        bench.state["binding"]["allowed_resources"] = [f"q831-{NONCE}-t08"]
    with pytest.raises(writer.PreparationRefused):
        await writer.prepare_read(target, RAW)
    assert bench.db["calls"] == [] and bench.bao_reads == []


def _bump(bench, key):
    def action():
        bench.state[key] += 1
    return action


@pytest.mark.parametrize("key", ["binding_revision", "token_revision", "policy_revision"])
async def test_revocation_a_r_pendant_admission_aucun_effet(bench, key):
    """Le changement survient au verrou de la transaction d'admission, après les faits."""
    bench.state["on_lock"] = _bump(bench, key)
    with pytest.raises(writer.PreparationRefused, match="admission_refused"):
        await writer.prepare_read(fact(), RAW)
    assert bench.db["calls"] == [] and bench.db["events"] == [] and bench.bao_reads == []


async def test_panne_bao_incertaine_jamais_confirmee(bench):
    """read_secret absorbe l'erreur backend : terminal unknown, jamais completed."""
    bench.state["bao_error"] = ConnectionError("PRIVATE-CANARY transport")
    with pytest.raises(writer.PreparationUncertain) as raised:
        await writer.prepare_read(fact(), RAW)
    assert raised.value.code == "read_not_confirmed" and "PRIVATE-CANARY" not in str(raised.value)
    assert raised.value.call_id == bench.db["calls"][0]["call_id"]
    assert phases(bench.db) == [("admission", "admitted"), ("bao_step_outcome", "unknown"),
                                ("public_terminal", "unknown")]


async def test_canary_different_lecture_reelle_mais_jeu_non_admis(bench):
    bench.state["bao"] = "autre-valeur"
    with pytest.raises(writer.PreparationUncertain, match="canary_mismatch"):
        await writer.prepare_read(fact(), RAW)
    # Les trois événements décrivent la vraie lecture ; aucun n'est ajouté ni retiré.
    assert phases(bench.db) == [("admission", "admitted"), ("bao_step_outcome", "confirmed"),
                                ("public_terminal", "completed")]


async def test_annulation_pendant_bao_terminal_unknown(bench):
    bench.state["bao_error"] = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await writer.prepare_read(fact(), RAW)
    assert phases(bench.db)[-1] == ("public_terminal", "unknown")
    assert ("public_terminal", "completed") not in phases(bench.db)


async def test_terminal_non_confirme_incertain(bench):
    bench.state["fail_commit_on"] = "public_terminal"
    with pytest.raises(writer.PreparationUncertain, match="terminal_unknown"):
        await writer.prepare_read(fact(), RAW)
    assert phases(bench.db) == [("admission", "admitted"), ("bao_step_outcome", "confirmed")]


async def test_admission_au_commit_inconnu_aucune_lecture(bench):
    bench.state["fail_commit_on"] = "admission"
    with pytest.raises(writer.PreparationUncertain, match="admission_unknown"):
        await writer.prepare_read(fact(), RAW)
    assert bench.bao_reads == []


def test_le_serveur_asgi_ne_charge_pas_le_writer():
    code = ("import sys, mcp_vault.server, mcp_vault.storage.audit_read; "
            "print('mcp_vault.storage.fixture831_writer' in sys.modules, "
            "'mcp_vault.storage.fixture831_job' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                         env={"PATH": "/usr/bin", "PYTHONPATH": "src"}, cwd=str(__import__("pathlib").Path(
                             __file__).resolve().parents[1]))
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "False False"


# -- Job privé : protocole -----------------------------------------------------------

class FakeJob:
    nonce = NONCE

    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    async def open(self):
        self.calls.append("open")

    async def prepare_read(self, **arguments):
        self.calls.append(("prepare_read", arguments))
        if self.fail:
            raise writer.PreparationUncertain("bao_unknown")
        return {"events": 3}

    async def close(self):
        self.calls.append("close")


def _serve(job, *lines):
    reader = io.BytesIO(b"".join(json.dumps(line).encode() + b"\n" for line in lines))
    out = io.BytesIO()
    code = asyncio.run(job_module.serve(job, reader, out))
    return code, [json.loads(x) for x in out.getvalue().splitlines()]


def test_job_ouvre_lit_puis_ferme():
    job = FakeJob()
    code, out = _serve(job, {"seq": 1, "action": "prepare_read", "arguments": {"mission_id": "m"}},
                       {"seq": 2, "action": "close", "arguments": {}})
    assert code == 0
    assert out == [{"seq": 0, "nonce": NONCE, "opened": True}, {"seq": 1, "result": {"events": 3}},
                   {"seq": 2, "result": None}]
    assert job.calls == ["open", ("prepare_read", {"mission_id": "m"}), "close"]


@pytest.mark.parametrize("lines", [
    [{"seq": 1, "action": "secret_read", "arguments": {}}],
    [{"seq": 2, "action": "close", "arguments": {}}],
    [{"seq": 1, "action": "close", "arguments": {"x": 1}}],
])
def test_job_commande_hors_contrat_arrete_sans_effet(lines):
    job = FakeJob()
    code, out = _serve(job, *lines, {"seq": 2, "action": "close", "arguments": {}})
    assert code == 1 and out[-1] == {"seq": 1, "error": "owner_result_uncertain"}
    assert job.calls == ["open"]


def test_job_incertitude_ferme_le_transport_sans_message():
    job = FakeJob(fail=True)
    code, out = _serve(job, {"seq": 1, "action": "prepare_read", "arguments": {}},
                       {"seq": 2, "action": "prepare_read", "arguments": {}})
    assert code == 1 and out[-1] == {"seq": 1, "error": "owner_result_uncertain"}
    assert len([c for c in job.calls if c != "open"]) == 1


def test_job_eof_sans_close_nest_pas_une_fermeture():
    code, _out = _serve(FakeJob())
    assert code == 1


def test_job_fichiers_prives_exiges(tmp_path, monkeypatch):
    bearer = tmp_path / "bearer"
    bearer.write_text(RAW)
    bearer.chmod(0o640)
    with pytest.raises(ValueError, match="private"):
        job_module.read_private(bearer)
    bearer.chmod(0o600)
    assert job_module.read_private(bearer) == RAW
    monkeypatch.delenv("Q831_BAO_READ_FILE", raising=False)
    with pytest.raises(ValueError, match="Bao read file"):
        job_module.main(["--nonce", NONCE, "--bearer-file", str(bearer)])
