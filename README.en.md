# 🔐 MCP Vault

> **Secure secret management for AI agents — embedded OpenBao**

> 🇫🇷 [Version française](README.md)

MCP Vault is an [MCP](https://modelcontextprotocol.io/) server that provides a secret vault for AI agents and missions. It embeds [OpenBao](https://openbao.org/) (open-source fork of HashiCorp Vault, Linux Foundation) as its encryption engine.

**Think 1Password, but for your AI agents.**

### 📸 Admin console

|               Dashboard                |          Vaults & Secrets           |          Audit & Alerts            |
| :------------------------------------: | :---------------------------------: | :--------------------------------: |
| ![Dashboard](screenshoots/screen1.png) | ![Vaults](screenshoots/screen2.png) | ![Audit](screenshoots/screen3.png) |

---

## 📖 Documentation

| Document                                                | Description                                                                                                                                                                  |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**ARCHITECTURE.md**](DESIGN/mcp-vault/ARCHITECTURE.md) | Full specification — vision, 6-layer ASGI architecture, vaults, SSH CA, MCP policies (6 ready-to-use examples), unseal key security (3 factors), HSM roadmap                  |
| [**TECHNICAL.md**](DESIGN/mcp-vault/TECHNICAL.md)       | Technical documentation — source modules (incl. PKI v0.5.1), 6-layer ASGI stack, Docker, tests, dependencies, roadmap                                                         |
| [**SECURITY_AUDIT.md**](DESIGN/mcp-vault/SECURITY_AUDIT.md) | Consolidated security audit report — 60 V2.1 findings, 28 fixed, 13 residual documented                                                                                   |
| [**scripts/README.md**](scripts/README.md)              | Full CLI guide — 7 command groups, interactive shell, examples                                                                                                               |
| [**tests/README.md**](tests/README.md)                  | Test execution guide — 4 levels, ~600 tests, commands for auditors                                                                                                           |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)            | e2e test catalog — 15 categories, 312 assertions, purpose of each section (for auditors)                                                                                     |

---

## ⚡ Quick start

```bash
# 1. Clone and configure
cp .env.example .env
# Adjust S3 credentials in .env

# 2. Build and start
docker compose build
docker compose up -d

# 3. Check (from the container)
docker compose exec mcp-vault python scripts/mcp_cli.py health

# 4. Test (312 e2e tests)
docker compose exec mcp-vault python tests/test_e2e.py
```

### Automatic lifecycle

On startup, MCP Vault:
1. Loads tokens from S3
2. Restores OpenBao data (Docker volume or S3)
3. Starts OpenBao, initializes it (first time) and unseals it
4. **Unseal keys**: encrypted (AES-256-GCM) on S3, never in cleartext on disk — only in memory
5. Enables periodic S3 sync (60s)

On shutdown (`docker compose stop`):
1. Seals OpenBao 🔒
2. Final upload to S3 📤
3. Stops the process — keys wiped from memory

---

## 🛠️ MCP tools (36)

### System (2)

| Tool            | Description                                       |
| --------------- | ------------------------------------------------- |
| `system_health` | Health status (OpenBao + S3)                      |
| `system_about`  | Service info (version, tools, platform)           |

> 💡 **Introspection**: the `/admin/api/whoami` endpoint and the `whoami` CLI command let you check the identity and permissions of the current token.

### Vaults — secret stores (5)

| Tool                                   | Perm  | Description                                            |
| -------------------------------------- | ----- | ------------------------------------------------------ |
| `vault_create(vault_id, description?)` | write | Creates a vault (KV v2 mount) + metadata (owner, date) |
| `vault_list()`                         | read  | Lists accessible vaults (filtered by token)            |
| `vault_info(vault_id)`                 | read  | Vault details (metadata, secrets_count, owner)         |
| `vault_update(vault_id, description)`  | write | Updates a vault's description                           |
| `vault_delete(vault_id, confirm)`      | admin | Deletes a vault and all its secrets ⚠️                |

### Secrets (6)

| Tool                                        | Perm  | Description                                   |
| ------------------------------------------- | ----- | --------------------------------------------- |
| `secret_write(vault_id, path, data, type?)` | write | Writes a typed secret                         |
| `secret_read(vault_id, path, version?)`     | read  | Reads a secret (latest version or specific)   |
| `secret_list(vault_id, path?)`              | read  | Lists a vault's keys                          |
| `secret_delete(vault_id, path)`             | write | Deletes a secret and all its versions         |
| `secret_types()`                            | read  | Lists the 14 secret types                     |
| `secret_generate_password(length?, ...)`    | read  | Generates a CSPRNG password                   |

### SSH Certificate Authority (5)

Each vault has its **own isolated SSH CA** — CAs are cryptographically distinct between vaults. A certificate signed by one vault's CA does NOT work on servers configured for another vault.

| Tool                                                 | Perm  | Description                                                |
| ---------------------------------------------------- | ----- | ---------------------------------------------------------- |
| `ssh_ca_setup(vault_id, role, allowed_users?, ttl?)` | write | Configures an SSH CA + role in a vault                     |
| `ssh_sign_key(vault_id, role, public_key, ttl?)`     | read  | Signs a public key → ephemeral certificate                 |
| `ssh_ca_public_key(vault_id)`                        | read  | CA public key (for `TrustedUserCAKeys` on servers)        |
| `ssh_ca_list_roles(vault_id)`                        | read  | Lists SSH CA roles configured in a vault                  |
| `ssh_ca_role_info(vault_id, role)`                   | read  | Role details (TTL, allowed_users, extensions)             |

### MCP Policies — granular access control (4)

Policies restrict the tools accessible per token, with support for **wildcards** (`system_*`, `ssh_*`...) and **per-vault rules** (`prod-*` → read-only).

| Tool                                                                                 | Perm  | Description                                         |
| ------------------------------------------------------------------------------------ | ----- | --------------------------------------------------- |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Creates a policy with access rules                  |
| `policy_list()`                                                                      | admin | Lists policies with counters                        |
| `policy_get(policy_id)`                                                              | admin | Full details (allowed/denied tools, path_rules)     |
| `policy_delete(policy_id, confirm)`                                                  | admin | Deletes a policy ⚠️                                |

> 📋 6 ready-to-use policies documented in [ARCHITECTURE.md §6.4.1](DESIGN/mcp-vault/ARCHITECTURE.md): `readonly`, `ssh-operator`, `developer`, `prod-reader-dev-writer`, `ci-cd-agent`, `security-auditor`

### Token Management (1)

| Tool                                                           | Perm  | Description                                             |
| -------------------------------------------------------------- | ----- | ------------------------------------------------------- |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)` | admin | Modifies an existing token (policy, permissions, vaults) |

> **Revoked-token purge** *(v0.7.0 — **admin** operation, exposed via REST / CLI / SPA; this is NOT an MCP tool)*: permanently deletes tokens revoked more than N days ago (retention, default 30). **Fail-close** (never an active token nor an expired-but-not-revoked one), **dry-run + confirmation**, rollback if S3 is unavailable, every purge **audited**. Via `POST /admin/api/tokens/purge`, the CLI command `token purge-revoked`, or the « 🧹 Purge revoked » button in the `/admin` console.

### Internal PKI — CA + ACME (8) *(v0.5.0)*

Sovereign CA for the ecosystem: Caddy WAFs enroll via ACME exactly like with Let's Encrypt, but on an internal CA isolated from the public network. Usable in lab (`*.lesur.lan`) and in air-gapped production.

| Tool | Perm | Description |
| --- | --- | --- |
| `pki_ca_setup(lab_mode, allowed_domains, leaf_ttl)` | admin | Initializes root + intermediate CA + ACME role |
| `pki_ca_public_key()` | read | Root CA PEM, SHA-256 fingerprint, stable URL |
| `pki_ca_list_roles()` | read | Lists issuance roles |
| `pki_ca_role_info(role_name)` | read | Role details (domains, TTL, TLS flags) |
| `pki_list_certs(limit?, offset?)` | admin | Paginated inventory of issued certificates |
| `pki_issue_cert(common_name, ttl?, alt_names?, ip_sans?)` | admin | Manual certificate issuance (off-ACME) — one-shot private key |
| `pki_revoke_cert(serial_number)` | admin | Revocation + CRL update |
| `pki_ca_rotate_intermediate(keep_old_issuer?, overlap_ttl?)` | admin | Intermediate CA rotation without downtime |

> Public endpoints (no-auth, standard ACME/PKI): `/acme/directory`, `/pki/ca/root.pem`, `/pki/ca/chain.pem`, `/pki/ca/crl.pem`
>
> **`PKI_BASE_URL`** (optional): base URL for CDPs and the OpenBao ACME cluster path. Empty = derived from `MCP_ALLOWED_HOSTS`. Docker test override: `http://mcp-vault:8030`. Must be `http(s)://`.

### JIT Wrap Broker + mediated consumption — C18 (4) *(v0.4.13 / v0.6.x)*

Contract for the mcp-mission `CredentialBrokerService`: single-use credential delivery via OpenBao response wrapping (cubbyhole), with a write-ahead registry on S3 for orphan compensation, and anti-confused-deputy validation (C18).

| Tool | Perm | Description |
| --- | --- | --- |
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds?, tenant_id?, expected_aud?)` | admin | Creates a single-use wrap token (write-ahead registry) |
| `secret_revoke_wrap(lease_id)` | admin | Idempotent revocation of a wrap token (not found = success) |
| `secret_wrap_lookup(operation_id)` | admin | Finds & revokes wraps by operation_id (orphan compensation #74) |
| `secret_consume(wrap_token, operation_id, mission_token)` | admin | Validates ES256/JWKS JWT, checks full binding (mission_id, tenant_id, aud), unwraps OpenBao (C18) |

> Enable C18 validation with `ENFORCE_MISSION_TOKEN_VALIDATION=true`. Default (false): log warning, continue — zero impact in standalone mode without mcp-mission.
> `tenant_id` and `expected_aud` in `secret_wrap` feed the full C18 binding on the `secret_consume` side *(v0.6.8)*.

### Mission JWT PEP — `/mcp` front door *(v0.8.0, #47 + #69)*

Second enforcement point (PEP) for the mcp-mission `mission_token` (ES256 JWT), **at the `/mcp` front door** (the first one being `secret_consume`/C18, at consumption). Driven by `MCP_AUTH_MODE`:

| Mode | `/mcp` behaviour |
| --- | --- |
| `bearer` *(default)* | Opaque bearer only — historical behaviour, **zero impact**. |
| `jwt` | `mission_token` JWT ES256 **required** (opaque bearer rejected). |
| `dual-stack` | Valid JWT **or** valid opaque bearer (migration). |

In `jwt`/`dual-stack`, the middleware **actively rejects**: `401` (missing/opaque/invalid JWT), `403` (`aud`/`component_id` ≠ instance, inactive mission), `503` (JWKS unavailable — fail-close). An invalid JWT **never** falls back to the bearer path. The token is checked against the real mcp-mission contract (`aud` contains `MCP_INSTANCE_ID`, `component_id["vault"] == MCP_INSTANCE_ID`, `iss`, `exp` leeway 0, `iat` anti-skew). The admin bootstrap key remains accepted (break-glass).

> A valid mission identity is **authenticated and instance-bound**, then mcp-vault (**local PDP**) resolves a **locally-provisioned vault scope** for it. Without a grant, **no access** (deny-by-default); infra tools (`system_*`, PKI inventory) and the admin plane (`vault_create/delete`, `ssh_*`) are denied to it. The admin endpoint `POST /admin/api/auth/jwks/reload` forces a JWKS reload (urgent `kid` revocation).

#### Vault-scope grant — `MissionBindingStore` *(#69)*

The `mission_token` carries **no** vault authorization: the grant is **provisioned locally**, keyed by `tenant_id` (stable claim), and stored one **file per instance** on S3.

- A grant ("binding") = `{tenant_id, allowed_resources:[vaults…], permissions, policy_id?, enabled, expires_at?}`.
- **Strict permissions**: `read` or `read,write` (never `write` alone, never `admin`). **Data-plane only**: read/write secrets in the allowed vaults — **never** create/destroy a vault nor manage an SSH CA.
- **Fail-close**: missing/disabled/expired binding → no access. **Store unavailable/corrupt → `503`** (observable denial, never a silent deny nor a destructive overwrite).
- **Administration** (bearer/bootstrap admin only — never via mission JWT):

```bash
mcp-cli mission-binding create acme-corp --vaults prod-app --permissions read
mcp-cli mission-binding create acme-corp --vaults prod-app,staging --permissions read,write
mcp-cli mission-binding list
mcp-cli mission-binding get acme-corp
mcp-cli mission-binding delete acme-corp
mcp-cli mission-binding purge --older-than 30 --dry-run   # expired bindings
```

> **Tenant granularity**: all active missions of the same client (`tenant_id`) share the granted scope. Per-mission granularity already exists at consumption time (`secret_consume`/C18).

### Audit (1)

| Tool                                                                       | Perm  | Description                                                              |
| -------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------- |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)` | admin | Filterable audit log (5000-entry ring buffer + persistent JSONL)        |

> **Access lifecycle audit trail** *(v0.7.0 — SecNumCloud/HDS compliance)*: every mutation of the access-control plane — token create / update / revoke / purge, policy create / delete — is logged, via the **admin REST API** as well as the **MCP tools**. Persistence failures of **removal** operations (revocation, purge, policy deletion — those that leave an access active if they fail) are also traced. The trace lives in `audit-mcp.jsonl`, **physically independent of `_system/tokens.json`** → it survives a purge. The raw token never appears in audit detail.

<details>
<summary>💡 Typical SSH CA workflow (e.g. LLMaaS infrastructure)</summary>

```python
# 1. Initial setup (ONE-TIME) — create vault + SSH roles
vault_create("llmaas-infra", description="SSH CA LLMaaS")
ssh_ca_setup("llmaas-infra", "adminct", allowed_users="adminct", ttl="1h")
ssh_ca_setup("llmaas-infra", "agentic", allowed_users="agentic,iaagentic", ttl="30m")

# 2. Deploy the CA on servers (ONE-TIME)
result = ssh_ca_public_key("llmaas-infra")
# → Put result["public_key"] in /etc/ssh/trusted-user-ca-keys.pem

# 3. Daily usage — sign a public key
cert = ssh_sign_key("llmaas-infra", "adminct", public_key="ssh-ed25519 AAAA...", ttl="1h")
# → cert["signed_key"] = signed certificate, valid 1h
# → OpenSSH uses it automatically when placed next to the private key
```

</details>

---

## 🔑 Secret types (1Password-style)

| Type            | Icon  | Required fields          | Usage                |
| --------------- | ----- | ------------------------ | -------------------- |
| `login`         | 🔑   | username, password       | Web/app credentials  |
| `password`      | 🔒   | password                 | Simple password      |
| `secure_note`   | 📝   | content                  | Secure notes         |
| `api_key`       | 🔌   | key                      | API keys             |
| `ssh_key`       | 🗝️ | private_key              | SSH key pairs        |
| `database`      | 🗄️ | host, username, password | DB connections       |
| `server`        | 🖥️ | host, username           | Server access        |
| `certificate`   | 📜   | certificate, private_key | TLS/SSL certificates |
| `env_file`      | 📄   | content                  | .env files           |
| `credit_card`   | 💳   | number, expiry, cvv      | Bank cards           |
| `identity`      | 👤   | name                     | Identities           |
| `wifi`          | 📶   | ssid, password           | Wi-Fi networks       |
| `crypto_wallet` | ₿     | *(all optional)*         | Crypto wallets       |
| `custom`        | ⚙️  | *(free fields)*          | Everything else      |

Each secret supports: `tags`, `favorite`, automatic KV v2 versioning.

---

## 🔒 Authentication

> ⚠️ **Only the `Authorization: Bearer <token>` header is accepted.** Query-string authentication (`?token=`) was removed for security reasons (v0.3.1).

```
Authorization: Bearer <token>
```

| Permission | Read | Write | Admin |
| ---------- | ---- | ----- | ----- |
| `read`     | ✅   | ❌    | ❌    |
| `write`    | ✅   | ✅    | ❌    |
| `admin`    | ✅   | ✅    | ✅    |

**3 isolation layers**:
1. **Vault-level**: `allowed_resources=[]` → owner-based (only vaults created by the token), or explicit list
2. **Tool-level**: policies with `allowed_tools`/`denied_tools` (fnmatch wildcards)
3. **Path-level**: `allowed_paths` in `path_rules` → control per individual secret

---

## 🖥️ CLI

MCP Vault includes a full CLI with Click + Rich + interactive shell:

```bash
# Scriptable commands
python scripts/mcp_cli.py health
python scripts/mcp_cli.py about
python scripts/mcp_cli.py whoami                       # Current token identity
python scripts/mcp_cli.py vault list
python scripts/mcp_cli.py vault create prod-servers -d "Prod SSH keys"
python scripts/mcp_cli.py secret write prod-servers web/github -d '{"username":"me","password":"s3cr3t"}' -t login
python scripts/mcp_cli.py secret read prod-servers web/github
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py token create agent-sre --vaults prod --policy readonly
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py token purge-revoked --older-than 30 --dry-run    # preview (nothing deleted)
python scripts/mcp_cli.py token purge-revoked --older-than 30 --yes        # effective purge
python scripts/mcp_cli.py policy create no-ssh -d "No SSH" --denied "ssh_*"
python scripts/mcp_cli.py policy create team-x --allowed "secret_*" --path-rules '[{"vault_pattern":"shared-*","allowed_paths":["shared/*"]}]'
python scripts/mcp_cli.py audit --status denied --limit 10

# Internal PKI (v0.5.0)
python scripts/mcp_cli.py pki setup --lab --domains '*.lesur.lan,lesur.lan'
python scripts/mcp_cli.py pki ca-key
python scripts/mcp_cli.py pki certs
python scripts/mcp_cli.py pki revoke 12:34:ab:cd:ef:12:34:56

# Interactive shell
python scripts/mcp_cli.py shell
```

> The `--help` of each command explains the 3-layer security model and guides the user.

See [scripts/README.md](scripts/README.md) for the full CLI documentation.

---

## ⚙️ Environment variables

Copy `.env.example` → `.env` and adjust. Variables are grouped by domain:

| Group | Variables | Required |
|--------|-----------|----------|
| **Server** | `MCP_SERVER_NAME`, `MCP_SERVER_PORT`, `MCP_ALLOWED_HOSTS` | Yes |
| **Auth** | `ADMIN_BOOTSTRAP_KEY` | Yes |
| **S3** | `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`, `S3_REGION_NAME` | Yes |
| **OpenBao** | `OPENBAO_ADDR`, `OPENBAO_SHARES`, `OPENBAO_THRESHOLD` | Yes |
| **Storage sync** | `VAULT_S3_PREFIX`, `VAULT_S3_SYNC_INTERVAL` | No |
| **PKI** *(v0.5.x)* | `PKI_BASE_URL` | No — overrides ACME URL in Docker tests |
| **Mission JWT** *(v0.6.x)* | `ENFORCE_MISSION_TOKEN_VALIDATION`, `MISSION_JWKS_URL`, `MISSION_TOKEN_AUD`, `MISSION_JWKS_CACHE_TTL`, `MISSION_STATUS_URL` | No — standalone without mcp-mission |
| **Mission JWT PEP** *(v0.8.0)* | `MCP_AUTH_MODE` (`bearer`/`jwt`/`dual-stack`), `MCP_INSTANCE_ID`, `MCP_COMPONENT_KIND` | No — default `bearer` = zero impact. `jwt`/`dual-stack` require `MISSION_JWKS_URL` + `MCP_INSTANCE_ID` |
| **CLI tokens** | `VAULT_WRAP_TOKEN`, `VAULT_MISSION_TOKEN` | No — export before the command, never in `.env` |

> **Sensitive CLI tokens**: `VAULT_WRAP_TOKEN` and `VAULT_MISSION_TOKEN` must NOT be stored in `.env` — they change on every operation. Pass them via `export` or inline:
> ```bash
> VAULT_WRAP_TOKEN=hvs.CAES... mcp-vault secret consume op-123
> ```

See `.env.example` for the full documentation of each variable.

---

## 🏗️ Architecture

> 📐 **Full documentation**: the [`DESIGN/mcp-vault/`](DESIGN/mcp-vault/) folder contains the detailed specification ([ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) — vision, security, SSH CA, policies, HSM roadmap) and the technical documentation ([TECHNICAL.md](DESIGN/mcp-vault/TECHNICAL.md) — modules, Docker, tests, dependencies).

```
Internet → WAF (Caddy + Coraza :8085) → MCP Vault (Python :8030) → OpenBao (:8200 localhost)
                  ↕ OWASP CRS v4                  ↕
              L7 protection                S3 Dell ECS (persistence)
```

### WAF — Caddy + Coraza (OWASP CRS v4)

The WAF protects the API against L7 attacks (SQL injection, XSS, LFI, RCE, SSRF):
- **Caddy v2.11.2** compiled with **coraza-caddy v2.2.0** via `xcaddy`
- **24 OWASP CoreRuleSet v4.7.0 rules** loaded
- **Blocking mode on ALL endpoints** (health, `/mcp`, `/admin/api`)
- **Targeted exclusions** (JSON-RPC false positives: French Unicode 920540, PowerShell names 932120; CA/CRL `.pem` distribution 920440) declared **before the CRS Include** ("exclusions before CRS" pattern) — required to neutralize phase:1 CRS rules
- **Security headers**: CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- Methods allowed per the MCP protocol: GET, POST, DELETE, PUT, PATCH

### ASGI stack (6 layers)
```
PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

`PkiMiddleware` (v0.5.0) is the outermost layer — it intercepts `/acme/*` and `/pki/ca/*.pem` before auth (public endpoints by PKI/ACME design).

### OpenBao lifecycle
```
STARTUP:  S3 download → bao server → init/unseal → periodic sync
RUNTIME:  secrets via hvac → S3 sync every 60s
SHUTDOWN: seal → final S3 upload → stop process
CRASH:    local Docker volume → immediate restart
```

### Unseal key security

OpenBao's unseal keys are protected by **3-factor physical separation**:

| Factor                                   | Storage                  | Compromise alone = insufficient    |
| ---------------------------------------- | ------------------------ | ---------------------------------- |
| **Encrypted data** (OpenBao barrier)     | Docker volume + S3       | Unreadable without unseal key      |
| **Unseal keys** (AES-256-GCM encrypted)  | S3 only                  | Undecryptable without bootstrap key |
| **ADMIN_BOOTSTRAP_KEY**                  | Env variable only        | Useless without the encrypted keys |

**Invariants**: unseal keys are **never** in cleartext on disk — only in memory during runtime. A crash automatically wipes the keys.

**Security roadmap**:

| Version              | Approach                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **v0.8.0** (current) | Keys on S3 encrypted AES-256-GCM+AAD, memory-only at runtime |
| **v1.0**             | Transit Auto-Unseal via dedicated OpenBao (Cloud Temple KMS)                                                        |
| **v2.0**             | **HSM connection** (Hardware Security Module) Cloud Temple — keys never leave the certified hardware module        |

> 📖 See [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 and §11 for full details.

---

## 📋 Tests (~600 tests, zero mocking)

> 📖 See [tests/README.md](tests/README.md) for the full execution guide.

```bash
# 1. CLI tests — parsing + display (197 tests, WITHOUT server)
python tests/test_cli_all.py

# 2. CLI LIVE tests — full cycle (79 tests, real server)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. MCP e2e tests (312 tests, in Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Crypto tests (18 tests, WITHOUT server — AES-256-GCM + AAD + entropy validation)
python tests/test_crypto.py

# A single CLI group
python tests/test_cli_all.py --only policy

# A single e2e group
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### e2e coverage (312 tests, 15 categories)

| Category               | Tests  | Description                                                                        |
| ---------------------- | ------ | ---------------------------------------------------------------------------------- |
| System                 | 7      | health, about, services, tools_count (36)                                          |
| Vault CRUD             | 28     | create + metadata, list, info + owner, update, delete, confirm, errors             |
| Secrets CRUD           | 24     | 10 types written, read/list/delete, validation                                     |
| Versioning             | 8      | v1→v2→v3, read latest, read specific                                               |
| Passwords              | 14     | lengths, options, exclusions, CSPRNG                                               |
| Isolation              | 7      | secrets partitioned between vaults                                                 |
| Errors                 | 10     | edge cases, missing vault, invalid type, `_vault_meta` protection                  |
| S3 Sync                | 3      | tar.gz archive on S3                                                               |
| SSH CA                 | 33     | setup, multiple roles, ed25519 signing, list/info roles, CA isolation, cleanup     |
| Types                  | 14     | 14 types verified individually                                                     |
| Admin API              | 15     | health, whoami, generate-password, logs, CSPRNG uniqueness                         |
| MCP Policies           | 43     | CRUD, validation, wildcards, path_rules, duplicates, errors, Admin API REST        |
| **Policy Enforcement** | **37** | check_policy, token_update, denied/allowed, policy change, Admin API               |
| **Audit Log**          | **31** | audit_log MCP, filters (category/tool/status/since/limit), stats, Admin API /audit |
| **WAF Security**       | **17** | LFI, SQLi, XSS, RCE, Scanner Detection → 403 + legitimate-request non-regression  |

---

## 📁 Project structure

```
mcp-vault/
├── .env.example              # Configuration (copy to .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Python dependencies
├── requirements.lock         # Pinned dependencies (exact versions)
├── VERSION                   # 0.8.0
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Detailed specification (v0.8.0)
│   ├── TECHNICAL.md          # Technical documentation (v0.8.0)
│   └── SECURITY_AUDIT.md     # Consolidated audit report (60 V2.1 findings)
├── scripts/
│   ├── mcp_cli.py            # CLI entry point
│   ├── README.md             # CLI documentation
│   └── cli/                  # CLI module (Click + Rich + prompt-toolkit)
│       ├── __init__.py       # Config (.env, BASE_URL, TOKEN)
│       ├── client.py         # MCPClient (Streamable HTTP)
│       ├── commands.py       # 7 Click groups
│       ├── display.py        # Rich display
│       └── shell.py          # Interactive shell
├── src/mcp_vault/
│   ├── config.py             # pydantic-settings configuration
│   ├── server.py             # FastMCP + 36 MCP tools + lifecycle + audit
│   ├── lifecycle.py          # startup/shutdown orchestrator
│   ├── s3_client.py          # Hybrid SigV2/SigV4 S3 client
│   ├── s3_sync.py            # File backend ↔ S3 sync
│   ├── auth/                 # Bearer tokens, check_access, ContextVar, jwt_validator
│   ├── admin/                # Web console /admin + REST API
│   ├── openbao/              # Process manager, HCL config, lifecycle
│   ├── vault/                # Spaces, secrets, SSH CA, PKI CA, wrapping, types
│   └── static/               # Admin SPA console (100% CLI parity)
│       ├── admin.html        # HTML structure + 7 modals
│       ├── css/admin.css     # Cloud Temple design (dark theme)
│       ├── js/               # 9 JS modules (config, api, app, dashboard, vaults, tokens, policies, activity, pki)
│       └── img/              # logo-cloudtemple.svg
├── tests/
│   ├── README.md             # Test execution guide (auditors)
│   ├── TEST_CATALOG.md       # Test catalog for auditors
│   ├── test_cli_all.py       # 197 CLI parsing tests (no server)
│   ├── test_cli_live.py      # 79 CLI live tests (real server)
│   ├── test_e2e.py           # 312 MCP e2e tests (15 categories)
│   ├── test_crypto.py        # 18 AES-256-GCM + AAD tests
│   ├── test_jwt_validator.py # C18 JWT validator tests (mission_token)
│   ├── test_wrap.py          # JIT wrap broker + C18 binding tests
│   ├── test_service.py       # low-level tests
│   ├── test_integration.py   # pytest tests
│   └── cli/                  # CLI tests split by group (7 files)
└── waf/                      # WAF Caddy + Coraza (OWASP CRS v4)
    ├── Dockerfile            # Multi-stage (xcaddy + CRS v4.7.0)
    ├── Caddyfile             # Reverse proxy + coraza_waf
    └── coraza.conf           # Coraza config + MCP exceptions
```

---

## 🌐 Cloud Temple MCP ecosystem

| Server           | Role                              | Port  |
| ---------------- | --------------------------------- | ----- |
| **MCP Tools**    | Toolbox (SSH, HTTP, shell)        | :8010 |
| **Live Memory**  | Shared working memory             | :8002 |
| **Graph Memory** | Long-term memory (graph)          | :8080 |
| **MCP Vault**    | 🔐 Secret vault                  | :8030 |
| **MCP Agent**    | Autonomous agent runtime          | :8040 |
| **MCP Mission**  | Mission orchestrator              | :8020 |

---

**License**: Apache 2.0 | **Author**: Cloud Temple | **Version**: 0.8.0
