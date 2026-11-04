"""Qualification HTTP/MCP publique, services réels admis explicitement.

Aucun service lancé, aucun nettoyage automatique. Les objets portent un run ID.
Le coordinateur lit les états persistants avant cleanup du domaine possédé.
"""
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("VAULT_PG_ADMITTED")!="yes",
    reason="Services réels : admission explicite et endpoints propres requis")


def require(condition,message):
    if not condition:
        pytest.fail(message,pytrace=False)


def assert_reserved_denial(status,result,token_scope=False):
    if token_scope:
        require(status==400 and result.get("status")=="error" and result.get("message")=="Périmètre de coffre refusé",
                "Allowlist technique : validation exacte non confirmée (503 ne vaut pas refus)")
    else:
        require(status==403 and result.get("status")=="error" and result.get("error_type")=="access_denied",
                "Garde technique : refus structurel exact non confirmé (503 ne vaut pas refus)")


def assert_revoked(status,result):
    require(status==401 and result.get("status")=="error" and result.get("message")=="Valid token required",
            "Révocation : refus401 exact requis, indisponibilité exclue")


@pytest.fixture(scope="module")
def deployment():
    import httpx
    run = os.environ.get("VAULT_PG_RUN_ID","")
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,23}",run)),"Run ID explicite requis")
    token = Path(os.environ["VAULT_PG_ADMIN_FILE"]).read_text().strip()
    url = os.environ["VAULT_PG_URL"].rstrip("/")
    ca = os.environ["VAULT_PG_HTTP_CA"]
    with httpx.Client(base_url=url,verify=ca,timeout=20,follow_redirects=False) as http:
        yield http,url,token,run


def rest(deployment,method,path,token=None,data=None):
    http,_,admin,_ = deployment
    response = http.request(method,"/admin/api/"+path,
        headers={"Authorization":"Bearer "+(admin if token is None else token)},json=data)
    try:
        result = response.json()
    except ValueError:
        pytest.fail("Réponse HTTP non JSON",pytrace=False)
    return response.status_code,result


def test_grant_access_batch_revoke_and_reserved(deployment):
    _,url,_,run = deployment
    coffer = "qual-"+run
    policy = "qual-"+run
    status,_ = rest(deployment,"POST","vaults",data={"vault_id":coffer})
    require(status==201,"Création coffre métier non confirmée")
    status,_ = rest(deployment,"POST","vaults/"+coffer+"/secrets",
        data={"path":"qualification","data":{"value":"public-fixture"},"create_only":True})
    require(status==200,"Secret témoin ordinaire non confirmé")
    status,_ = rest(deployment,"POST","policies",data={"policy_id":policy,
        "allowed_tools":["vault_info","vault_metadata_batch","secret_read","secret_list"],
        "denied_tools":[],"path_rules":[]})
    require(status==201,"Création policy non confirmée")
    status,created = rest(deployment,"POST","tokens",data={"client_name":coffer,
        "permissions":["read"],"allowed_resources":[coffer],"policy_id":policy,"expires_in_days":1})
    require(status==201 and isinstance(created.get("raw_token"),str),"Octroi token non confirmé")
    token = created["raw_token"]
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    status,batch = rest(deployment,"POST","vaults/metadata-batch",token=token,
        data={"vault_ids":[coffer],"limit":1})
    require(status==200 and batch.get("total")==1,"Batch autorisé non confirmé")
    # SDK MCP/CLI public, même bearer et endpoint TLS explicitement configuré.
    import sys
    sys.path.insert(0,str(Path(__file__).parents[2]/"scripts"))
    from cli.client import MCPClient
    previous = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = os.environ["VAULT_PG_HTTP_CA"]
    try:
        result = asyncio.run(MCPClient(url,token,timeout=20).call_tool("secret_read",
            {"vault_id":coffer,"path":"qualification"}))
        require(result.get("status")=="ok" and result.get("data")=={"value":"public-fixture","_type":"custom","_tags":"","_favorite":"false"},"Valeur du secret témoin MCP incorrecte")
        result = asyncio.run(MCPClient(url,token,timeout=20).call_tool("vault_metadata_batch",
            {"vault_ids":[coffer],"limit":1}))
        require(result.get("status")=="ok" and result.get("total")==1,"Batch MCP non confirmé")
    finally:
        if previous is None:
            os.environ.pop("SSL_CERT_FILE",None)
        else:
            os.environ["SSL_CERT_FILE"] = previous
    # Projections console/SSH complètes : lot B explicite, pas preuve du lot A.
    reserved = os.environ["VAULT_PG_RESERVED_MOUNT"]
    for method,path,data in (("GET","vaults/"+reserved,None),
            ("DELETE","vaults/"+reserved,None),
            ("GET","vaults/"+reserved+"/secrets",None),
            ("POST","vaults/metadata-batch",{"vault_ids":[coffer,reserved]}),
            ("POST","tokens",{"client_name":coffer+"-bad","permissions":["read"],"allowed_resources":[reserved]})):
        status,result = rest(deployment,method,path,data=data)
        assert_reserved_denial(status,result,token_scope=path=="tokens")
    status,_ = rest(deployment,"DELETE","tokens/"+token_hash[:12])
    require(status==200,"Révocation non confirmée")
    status,refusal = rest(deployment,"GET","whoami",token=token)
    assert_revoked(status,refusal)
    # Preuve PRIVÉE utilisée par la phase finale dans un processus neuf.
    evidence = Path(os.environ["VAULT_PG_PRIVATE_EVIDENCE"])
    descriptor = os.open(evidence,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,"w") as output:
        json.dump({"run":run,"coffer":coffer,"policy":policy,"revoked_token":token,
                   "token_hash":token_hash,"initial_confirmation":"confirmed"},output)
        output.flush()
        os.fsync(output.fileno())


def test_bootstrap_business_closed(deployment):
    bootstrap = Path(os.environ["VAULT_PG_BOOTSTRAP_FILE"]).read_text().strip()
    status,_ = rest(deployment,"GET","whoami",token=bootstrap)
    require(status==403,"Bootstrap utilisé comme admin métier")


def test_final_after_new_process(deployment):
    # Exécuter ce test SEUL dans un nouveau processus après restart/restore.
    if os.environ.get("VAULT_PG_FINAL")!="yes":
        pytest.skip("Phase finale distincte après restart/restore réel")
    evidence = json.loads(Path(os.environ["VAULT_PG_PRIVATE_EVIDENCE"]).read_text())
    status,refusal = rest(deployment,"GET","whoami",token=evidence["revoked_token"])
    assert_revoked(status,refusal)
    status,batch = rest(deployment,"POST","vaults/metadata-batch",
        data={"vault_ids":[evidence["coffer"]]})
    require(status==200 and batch.get("total")==1,"État final du coffre absent")
    status,_ = rest(deployment,"POST","policies",data={"policy_id":evidence["policy"],
        "allowed_tools":["vault_info"],"denied_tools":[],"path_rules":[]})
    require(status==400,"Collision policy attendue après restart/restore (outage ne prouve pas persistance)")
