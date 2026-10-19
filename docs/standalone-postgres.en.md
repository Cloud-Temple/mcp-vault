# Standalone PostgreSQL operations

This guide accompanies [#187](https://github.com/Cloud-Temple/mcp-vault/issues/187),
the corrective follow-up to [#186](https://github.com/Cloud-Temple/mcp-vault/issues/186)
under [EPIC #824](https://github.com/Cloud-Temple/mcp-mission/issues/824).
[PG #178](https://github.com/Cloud-Temple/mcp-vault/issues/178) and
[audit #179](https://github.com/Cloud-Temple/mcp-vault/issues/179) remain the product
contracts. See the detailed [French commands](standalone-postgres.md) and
[acceptance matrix](standalone-validation.md).

**Evidence is local software testing only.** Native PG/TLS/Bao authentication,
images, restart and logical restore remain unqualified. The previously qualified
server version is UNKNOWN. The recipe tag `postgres:16`, client tools and loaded
libpq are distinct from the actual server. Measure each; never infer server
compatibility from libpq. Role operations require an observed PG16+ server.

| Application | PG | Preparation |
| --- | --- | --- |
| Compose | Single local engine | Base plus postgres override, one private engine and persistent volume |
| Compose | External dedicated/shared | Base only, external operator prepares TLS and control privileges |
| Local Python | Single local engine | Python 3.12, isolated venv, requirements.lock, Bao in PATH, separately prepared engine |
| Local Python | External dedicated/shared | Same application/dependencies, external TLS endpoint and control database |

All paths keep the production image, API, schemas, scopes, TTLs, secret provider
and S3/OpenBao authority. There is no factory dependency, runtime SQL provider,
automatic migration, HA or PITR. Starter kits may be copied manually later.
[OpenBao without S3 #102](https://github.com/Cloud-Temple/mcp-vault/issues/102) and
[WAF Settings #105](https://github.com/Cloud-Temple/mcp-vault/issues/105) remain
separate work.

## Prepare and install

Use a private copy of [operator.json](examples/standalone-operator.json). Select
source_fresh, copy or return explicitly. Unknown fields, reused paths and
colliding database names are refused. All credentials, including infra, backup
and restore, remain in **one reserved mount M** across Source/Copy/Return. Only
their paths change. A new mount would expose the old technical mount to business
routes. Prepare a fresh A domain plus an independently administered B witness;
record B's ACLs and business reads before/after without granting B to infra A.

Keep directories 0700, private inputs/Settings/carriers/archives 0600, outside
Git and the build context. The six input files infra/app/provisioner/maintenance/
backup/restore.json each contain exactly five nonempty strings: host, port,
dbname, user, password. They are installed CAS 0 without overwrite. Subsequent
connections always reread native Bao after lookup-self, including probes and
dump/restore. No SQL DSN, application SQL password environment or alternate
provider is accepted. Host must match the certificate SAN.

Infra uses a separate control database, typically postgres, with explicit
CONNECT. It is NON superuser, CREATEDB/CREATEROLE, without replication or bypass
RLS. These are **cluster-wide powers**, not containment against compromised
infra. ADMIN rights on roles it creates remain relevant; no B membership is
allowed. Owner is NOLOGIN. The five login roles are distinct NOINHERIT identities
without dangerous attributes. Only provisioner/backup/restore can SET ROLE owner,
with ADMIN FALSE and INHERIT FALSE. App/maintenance have no membership.
Backup/restore effectively exercise owner authority for A.

Use the actual application Settings file and loader, not a parallel S3 config.
The bootstrap subprocess uses an explicit cwd and clean environment. It retains
root_token only and immediately discards keys/keys_base64, without init, unseal,
legacy migration or set_hvac_client. Token-file refusal never falls back to S3.
Prepare Bao/unseal/auth **before all SQL**. Bao remains HTTP loopback with TLS
disabled: vault_ca_file offers no TLS protection there. Application HTTPS CA and
PG verify-full CA are distinct.

prepare-files generates fresh TLS files and a matching SAN. Measure PG UID/GID,
rather than assuming 999. Keep the server key 0600 for PG, mount the CA read-only
for the app UID, and never mount the CA private key. Compose interpolation
(compose.env: VAULT_ENV_FILE, PG_CA_FILE, OPERATOR_DIRECTORY, local TLS/engine
directories) is separate from Settings. Set METADATA_PG_CA_FILE=/run/pg-ca.crt.
The default README mount preserves S3 mode; it is not a PG CA. Caddy variables
SITE_ADDRESS/WAF_TLS_DIRECTIVE belong to interpolation, not unknown Settings.

Start Vault/Bao privately first, without WAF exposure or implicit PG dependency.
The script does not manage services. Run install with the private credential
directory. For a new local engine, prepare-engine then writes fixed infra init
and a separate engine password after native auth. Start the sole PG engine with
those files and persistent volume. External preparation belongs to its operator.
Existing volumes are not migrated. The pg-operator target contains scripts and
PG clients, sharing Vault's loopback network without publishing Bao. Production
is unchanged. Adapt JSON paths to container mounts and its measured non-root UID.

The generated engine HBA refuses non-TLS TCP and requires SCRAM over TLS. Unix
bootstrap remains private to the engine container; its socket is not mounted
into the application.

For Python, install requirements.lock in a Python 3.12 venv; run python -m
mcp_vault from the private Settings cwd with PYTHONPATH pointing to public src,
Bao in PATH and private data/config/log paths. Prepare public TLS and allowlists
before exposure. No Mission cluster is required for default standalone v2.

The effective Settings file must be named `.env`, as the application's real
get_settings reads that name in its cwd. Start Python with a clean environment
(env -i, explicitly supplied venv/Bao PATH and source PYTHONPATH) so old Settings
variables cannot override it. Compose supplies that same file through
VAULT_ENV_FILE, separately from interpolation. One operator runs one action at
a time; carriers are not a locking service.

provision-fresh prevalidates credentials, measures PG, refuses role/DB collisions,
prepares identities/ACLs, then explicitly invokes schema-init and initial-admin.
It cannot run in Copy/Return. Choose the profile at installation: v2 default;
Mission-retention flag for v3; existing explicit audit-retirement-upgrade from
v3 for v4. Changing flags after v2 never migrates or repairs. Maintenance retains
the existing #179 authority and retention behavior. verify checks KV connections
only. After restarting DISABLED, verify-disabled requires canonical operator
denial and /health 200. An intent without ACK stops, without retrying seed/DDL.

## Copy and safe return

Stop Source Vault and its Bao together. Resume the same current Bao volume with
one private Copy process, same M/instance/owner and new Copy paths. Credentials
keep host/user/password; dbname changes. Copy INSTALL dispatches only connections
and audit-maintenance-connection, plus native CAS 0 for operator credentials.
Never run install-vault, schema-init, initial-admin or upgrades on Copy. This is
a script restriction: the raw product INSTALL route still permits those acts.
Restart RESTORE and authenticate native Bao before SQL.

The sequence is create-copy → freeze-source → dump-frozen → seal-source →
restore-frozen → verify-copy. Copy must be absent, template0, owner A, no PUBLIC,
initial CONNECT only for infra/backup/restore. Custom dumps without --create omit
database CONNECT ACLs: the operator prepares these explicitly. GRANT/REVOKE use
the same owner grantor and verify actual datacl plus effective rights. Object
ACLs, schema and seed come from the archive.

SourceFrozen removes business/restore CONNECT and drains exact A sessions,
retaining backup until dump completes. Unknown/neighbor sessions are not signaled.
Only an exclusive archive created after confirmed freeze, with stable contents
before/after, exit 0 and verified hash, is admissible. SourceSealed revokes backup/
infra CONNECT, sets ALLOW_CONNECTIONS false and confirms zero sessions. Restore
uses one transaction, exit-on-error and the same owner, without remapping.
Private carriers bind config, M, paths, OIDs, ACLs, archive and contents; live
observations remain authoritative.

Use separate fresh domains for two scenarios. For **proven zero Copy business
mutation**, require matching baseline, closed ACLs, zero sessions and no calls,
exposure or dirty intent. Decide rollback-zero, then use the named
reopen-source-zero action, with private Source Settings in RESTORE and the same
current Bao/one process. It closes Copy and restores Source's exact ACL/ALLOW.
Restart Source DISABLED and verify before exposure. Failed/UNKNOWN restore only
permits this with real proof of a fully rolled-back transaction or complete
stable result **and every other zero predicate**. Missing files prove nothing.

Before **any Copy business call**, even read/denial that may audit, record-copy-
mutation, then open-copy-private. The old Source is forbidden thereafter. After
positive mutations, revocation and audit, freeze Copy, produce a fresh dump, seal
Copy and restore into new A_return using return context and new carriers. Verify
the mutation, current revocation and audit before DISABLED/exposure. No invented
reconciliation with stale archives. If privileged work occurred outside this
protocol, zero is unknown and old Source cannot resume.

Unknown results, incomplete observations or divergence preserve both sides
closed. Qualify all four paths with the existing admitted public-interface tests
and a new process after restart/restore, plus independent A/B checks. Record real
server/libpq/client/image versions. A 503 is not isolation; a 401 with unavailable
storage is not revocation. PG logical restore does not restore Bao history or the
application JSONL journal; journal restore remains UNKNOWN until measured.
Preserve volumes, archives and receipts; stop only owned resources after confirmed
revocation, without down -v. Independent plan and final diff/result reviews with
real project-memory reading remain required. This guide claims no native PASS.
