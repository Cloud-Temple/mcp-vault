#!/usr/bin/env python3
"""Opérations infrastructure finies du domaine, auth native Vault avant SQL.

Cet outil PUBLIC est exécuté par l'opérateur externe, jamais par l'app Vault.
Il ne lit aucun DSN/credential SQL direct ou fallback dans l'environnement.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

# L'import par chemin est également utilisé par les tests publics #178.
sys.path.insert(0,str(Path(__file__).resolve().parent))


def native_connection(args,mount,path):
    import httpx
    token = Path(args.vault_token_file).read_text().strip()
    if not token:
        raise ValueError()
    with httpx.Client(verify=args.vault_ca_file,timeout=httpx.Timeout(5,connect=1),follow_redirects=False) as http:
        headers = {"X-Vault-Token":token}
        # Auth indépendante PG établie AVANT lecture de credentials/SQL.
        def read(suffix):
            end = time.monotonic()+5
            with http.stream("GET",args.vault_url.rstrip("/")+"/v1/"+suffix,headers=headers) as response:
                if response.status_code!=200:
                    raise ValueError()
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunks)+len(chunk)>65536 or time.monotonic()>=end:
                        raise ValueError()
                    chunks.extend(chunk)
                return json.loads(chunks)
        read("auth/token/lookup-self")
        data = read(quote(mount,safe="")+"/data/"+quote(path,safe="/"))["data"]["data"]
    if (set(data)!={"host","port","dbname","user","password"}
            or not all(isinstance(v,str) and v for v in data.values()) or not data["port"].isdigit()):
        raise ValueError()
    return data


def operation(args):
    import psycopg
    if args.action=="provision" and args.infra_mount!=args.domain_mount:
        raise ValueError("Un seul mount technique réservé requis")
    # Aucune lecture du fournisseur après connexion qui pourrait être un fallback.
    credential = native_connection(args,args.infra_mount,args.infra_path)
    if args.action=="provision":
        # Toutes les intentions, dont maintenance, AVANT le premier connect.
        from standalone_pg_sql import KINDS, provision
        values = {"infra":credential}
        for kind in KINDS:
            values[kind] = native_connection(args,args.domain_mount,getattr(args,kind+"_path"))
        return provision(args,values)
    credential["dbname"] = args.database
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("PG"):
            del environment[name]
    environment.update({"PGHOST":credential["host"],"PGPORT":credential["port"],
        "PGDATABASE":args.database,"PGUSER":credential["user"],"PGPASSWORD":credential["password"],
        "PGSSLMODE":"verify-full","PGSSLROOTCERT":args.pg_ca_file,"PGCONNECT_TIMEOUT":"3"})
    if args.action=="dump":
        # O_EXCL : ne jamais écraser une archive/preuve existante.
        descriptor = os.open(args.archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,"wb") as output:
            process = subprocess.run(["pg_dump","--format=custom","--no-password"],env=environment,stdout=output,stderr=subprocess.DEVNULL,timeout=120,check=False)
    elif args.action=="restore":
        # L'opérateur a créé la base neuve ET restauré les rôles/grants séparément.
        with psycopg.connect(**credential,sslmode="verify-full",sslrootcert=args.pg_ca_file,connect_timeout=3) as conn:
            if conn.execute("SELECT 1 FROM pg_namespace WHERE nspname='vault_metadata'").fetchone():
                raise ValueError()
        process = subprocess.run(["pg_restore","--dbname",args.database,"--single-transaction","--exit-on-error","--no-password",args.archive],env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,check=False)
    else:
        raise ValueError()
    if process.returncode:
        raise ValueError()
    return {"status":"ok","action":args.action,"domain":args.database}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("provision","dump","restore"))
    for name in ("vault-url","vault-token-file","vault-ca-file","infra-mount","infra-path","pg-ca-file","database"):
        parser.add_argument("--"+name,required=True)
    for name in ("owner-role","app-role","provisioner-role","maintenance-role","backup-role","restore-role","domain-mount","app-path","provisioner-path","maintenance-path","backup-path","restore-path","archive"):
        parser.add_argument("--"+name)
    args = parser.parse_args()
    identifiers = [args.database]+([args.owner_role,args.app_role,args.provisioner_role,args.domain_mount] if args.action=="provision" else [])
    if not all(isinstance(v,str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}",v) for v in identifiers):
        parser.error("Identités explicites canoniques requises")
    if args.action=="provision":
        kinds = ("owner","app","provisioner","maintenance","backup","restore")
        roles = [getattr(args,k+"_role") for k in kinds]
        paths = [getattr(args,k+"_path") for k in kinds[1:]]
        if len(set(roles))!=6 or any(not role for role in roles) or len(set(paths))!=5 or any(not p for p in paths):
            parser.error("Six rôles et cinq chemins distincts requis")
    if args.action in {"dump","restore"} and not args.archive:
        parser.error("Archive privée requise")
    try:
        print(json.dumps(operation(args)))
    except Exception:  # noqa: BLE001 - boundary deliberately redacts credentials
        # Ne jamais afficher SQL, credential, DSN, backend exception ou subprocess stderr.
        print(json.dumps({"status":"error","message":"Action non confirmée ; arrêt, constater sans rejouer"}))
        return 1
    return 0


if __name__=="__main__":
    sys.exit(main())
