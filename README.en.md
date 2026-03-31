# 🔐 MCP Vault

> **Secure secrets management for AI agents — OpenBao embedded**

> 🇫🇷 [Version française](README.md)

MCP Vault is an [MCP](https://modelcontextprotocol.io/) server that provides a secrets vault for AI agents and missions. It embeds [OpenBao](https://openbao.org/) (open-source fork of HashiCorp Vault, Linux Foundation) as its encryption engine.

**Think 1Password, but for your AI agents.**

### 📸 Admin Console

|               Dashboard                |          Vaults & Secrets           |          Audit & Alerts            |
| :------------------------------------: | :---------------------------------: | :--------------------------------: |
| ![Dashboard](screenshoots/screen1.png) | ![Vaults](screenshoots/screen2.png) | ![Audit](screenshoots/screen3.png) |

---

## 📖 Documentation

| Document                                                     | Description                                                                                                                              |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| [**ARCHITECTURE.md**](DESIGN/mcp-vault/ARCHITECTURE.md)      | Full specification — vision, 5-layer ASGI architecture, vaults, SSH CA, MCP policies (6 ready-to-use examples), unseal key security (3 factors), HSM roadmap |
| [**TECHNICAL.md**](DESIGN/mcp-vault/TECHNICAL.md)            | Technical documentation — 14 source modules, data model, Docker, 312 e2e tests, dependencies, roadmap                                   |
| [**SECURITY_AUDIT.md**](DESIGN/mcp-vault/SECURITY_AUDIT.md)  | Consolidated security audit report — 60 V2.1 findings, 28 fixed, 13 residual documented                                                 |
| [**scripts/README.md**](scripts/README.md)                   | Complete CLI guide — 7 command groups, interactive shell, examples                                                                        |
| [**tests/README.md**](tests/README.md)                       | Test execution guide — 4 levels, ~600 tests, commands for auditors                                                                       |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)                 | E2e test catalog — 15 categories, 312 assertions, section objectives (for auditors)                                                      |

---

## ⚡ Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit S3 credentials in .env

# 2. Build and start
docker compose build
docker compose up -d

# 3. Verify (from container)
docker compose exec mcp-vault python scripts/mcp_cli.py health

# 4. Test (312 e2e tests)
docker compose exec mcp-vault python tests/test_e2e.py
```

### Automatic Lifecycle

On startup, MCP Vault:
1. Loads tokens from S3
2. Restores OpenBao data (Docker volume or S3)
3. Starts OpenBao, initializes (first time) and unseals it
4. **Unseal keys**: encrypted (AES-256-GCM) on S3, never in cleartext on disk — memory only
5. Starts periodic S3 sync (60s)

On shutdown (`docker compose stop`):
1. Seals OpenBao 🔒
2. Final upload to S3 📤
3. Stops the process — keys wiped from memory

---

## 🛠️ MCP Tools (24)

### System (2)

| Tool            | Description                                  |
| --------------- | -------------------------------------------- |
| `system_health` | Health status (OpenBao + S3)                 |
| `system_about`  | Service info (version, tools, platform)      |

> 💡 **Introspection**: the `/admin/api/whoami` endpoint and `whoami` CLI command let you verify the current token's identity and permissions.

### Vaults — Secret Stores (5)

| Tool                                   | Perm  | Description                                          |
| -------------------------------------- | ----- | ---------------------------------------------------- |
| `vault_create(vault_id, description?)` | write | Creates a vault (KV v2 mount) + metadata (owner, date) |
| `vault_list()`                         | read  | Lists accessible vaults (filtered by token)          |
| `vault_info(vault_id)`                 | read  | Vault details (metadata, secrets_count, owner)       |
| `vault_update(vault_id, description)`  | write | Updates a vault's description                        |
| `vault_delete(vault_id, confirm)`      | admin | Deletes a vault and all its secrets ⚠️             |

### Secrets (6)

| Tool                                        | Perm  | Description                                       |
| ------------------------------------------- | ----- | ------------------------------------------------- |
| `secret_write(vault_id, path, data, type?)` | write | Writes a typed secret                             |
| `secret_read(vault_id, path, version?)`     | read  | Reads a secret (latest or specific version)       |
| `secret_list(vault_id, path?)`              | read  | Lists keys in a vault                             |
| `secret_delete(vault_id, path)`             | write | Deletes a secret and all its versions             |
| `secret_types()`                            | read  | Lists the 14 secret types                        |
| `secret_generate_password(length?, ...)`    | read  | Generates a CSPRNG password                       |

### SSH Certificate Authority (5)

Each vault has its **own isolated SSH CA** — CAs are cryptographically different between vaults. A certificate signed by one vault's CA does NOT work on servers configured for another vault.

| Tool                                                 | Perm  | Description                                                  |
| ---------------------------------------------------- | ----- | ------------------------------------------------------------ |
| `ssh_ca_setup(vault_id, role, allowed_users?, ttl?)` | write | Configures an SSH CA + role in a vault                       |
| `ssh_sign_key(vault_id, role, public_key, ttl?)`     | read  | Signs a public key → ephemeral certificate                   |
| `ssh_ca_public_key(vault_id)`                        | read  | CA public key (for `TrustedUserCAKeys` on servers)           |
| `ssh_ca_list_roles(vault_id)`                        | read  | Lists SSH CA roles configured in a vault                     |
| `ssh_ca_role_info(vault_id, role)`                   | read  | Role details (TTL, allowed_users, extensions)                |

### MCP Policies — Granular Access Control (4)

Policies allow fine-grained restriction of tools accessible per token, with **wildcard** support (`system_*`, `ssh_*`...) and **per-vault rules** (`prod-*` → read-only).

| Tool                                                                                 | Perm  | Description                                          |
| ------------------------------------------------------------------------------------ | ----- | ---------------------------------------------------- |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Creates a policy with access rules                   |
| `policy_list()`                                                                      | admin | Lists policies with counters                         |
| `policy_get(policy_id)`                                                              | admin | Full details (allowed/denied tools, path_rules)      |
| `policy_delete(policy_id, confirm)`                                                  | admin | Deletes a policy ⚠️                                |

> 📋 6 ready-to-use policies documented in [ARCHITECTURE.md §6.4.1](DESIGN/mcp-vault/ARCHITECTURE.md): `readonly`, `ssh-operator`, `developer`, `prod-reader-dev-writer`, `ci-cd-agent`, `security-auditor`

### Token Management (1)

| Tool                                                           | Perm  | Description                                                |
| -------------------------------------------------------------- | ----- | ---------------------------------------------------------- |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)` | admin | Modify an existing token (policy, permissions, vaults)     |

### Audit (1)

| Tool                                                                       | Perm  | Description                                                              |
| -------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------ |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)` | admin | Filterable audit log (5000-entry ring buffer + persistent JSONL)         |

<details>
<summary>💡 Typical SSH CA Workflow (e.g., LLMaaS infrastructure)</summary>

```python
# 1. Initial setup (ONE-TIME) — create vault + SSH roles
vault_create("llmaas-infra", description="SSH CA LLMaaS")
ssh_ca_setup("llmaas-infra", "adminct", allowed_users="adminct", ttl="1h")
ssh_ca_setup("llmaas-infra", "agentic", allowed_users="agentic,iaagentic", ttl="30m")

# 2. Deploy CA to servers (ONE-TIME)
result = ssh_ca_public_key("llmaas-infra")
# → Put result["public_key"] in /etc/ssh/trusted-user-ca-keys.pem

# 3. Daily usage — sign a public key
cert = ssh_sign_key("llmaas-infra", "adminct", public_key="ssh-ed25519 AAAA...", ttl="1h")
# → cert["signed_key"] = signed certificate, valid for 1h
# → OpenSSH uses it automatically when placed alongside the private key
```

</details>

---

## 🔑 Secret Types (1Password-style)

| Type            | Icon  | Required Fields          | Usage              |
| --------------- | ----- | ------------------------ | ------------------ |
| `login`         | 🔑   | username, password       | Web/app credentials |
| `password`      | 🔒   | password                 | Simple password    |
| `secure_note`   | 📝   | content                  | Secure notes       |
| `api_key`       | 🔌   | key                      | API keys           |
| `ssh_key`       | 🗝️ | private_key              | SSH key pairs      |
| `database`      | 🗄️ | host, username, password | DB connections     |
| `server`        | 🖥️ | host, username           | Server access      |
| `certificate`   | 📜   | certificate, private_key | TLS/SSL certs      |
| `env_file`      | 📄   | content                  | .env files         |
| `credit_card`   | 💳   | number, expiry, cvv      | Credit cards       |
| `identity`      | 👤   | name                     | Identities         |
| `wifi`          | 📶   | ssid, password           | Wi-Fi networks     |
| `crypto_wallet` | ₿     | *(all optional)*         | Crypto wallets     |
| `custom`        | ⚙️  | *(free-form fields)*     | Everything else    |

Every secret supports: `tags`, `favorite`, automatic KV v2 versioning.

---

## 🔒 Authentication

> ⚠️ **Only the `Authorization: Bearer <token>` header is accepted.** Query string authentication (`?token=`) was removed for security reasons (v0.3.1).

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
3. **Path-level**: `allowed_paths` in `path_rules` → per-secret access control

---

## 🖥️ CLI

MCP Vault includes a complete CLI with Click + Rich + interactive shell:

```bash
# Scriptable commands
python scripts/mcp_cli.py health
python scripts/mcp_cli.py about
python scripts/mcp_cli.py whoami                       # Current token identity
python scripts/mcp_cli.py vault list
python scripts/mcp_cli.py vault create prod-servers -d "SSH keys prod"
python scripts/mcp_cli.py secret write prod-servers web/github -d '{"username":"me","password":"s3cr3t"}' -t login
python scripts/mcp_cli.py secret read prod-servers web/github
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py token create agent-sre --vaults prod --policy readonly
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py policy create no-ssh -d "No SSH" --denied "ssh_*"
python scripts/mcp_cli.py policy create team-x --allowed "secret_*" --path-rules '[{"vault_pattern":"shared-*","allowed_paths":["shared/*"]}]'
python scripts/mcp_cli.py audit --status denied --limit 10

# Interactive shell
python scripts/mcp_cli.py shell
```

> Each command's `--help` explains the 3-layer security model and guides the user.

See [scripts/README.md](scripts/README.md) for the complete CLI documentation.

---

## 🏗️ Architecture

> 📐 **Full documentation**: the [`DESIGN/mcp-vault/`](DESIGN/mcp-vault/) folder contains the detailed specification ([ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) — vision, security, SSH CA, policies, HSM roadmap) and the technical documentation ([TECHNICAL.md](DESIGN/mcp-vault/TECHNICAL.md) — modules, Docker, tests, dependencies).

```
Internet → WAF (Caddy + Coraza :8085) → MCP Vault (Python :8030) → OpenBao (:8200 localhost)
                  ↕ OWASP CRS v4                  ↕
              L7 Protection                 S3 Dell ECS (persistence)
```

### WAF — Caddy + Coraza (OWASP CRS v4)

The WAF protects the API against L7 attacks (SQL injection, XSS, LFI, RCE, SSRF):
- **Caddy v2.11.2** compiled with **coraza-caddy v2.2.0** via `xcaddy`
- **24 OWASP CoreRuleSet v4.7.0 rules** loaded
- **Blocking mode on ALL endpoints** (health, `/mcp`, `/admin/api`)
- **2 targeted exclusions** for JSON-RPC false positives: French Unicode (920540), PowerShell names (932120)
- **Security headers**: CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- MCP-compatible allowed methods: GET, POST, DELETE, PUT, PATCH

### ASGI Stack (5 layers)
```
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

### OpenBao Lifecycle
```
STARTUP:  S3 download → bao server → init/unseal → periodic sync
RUNTIME:  secrets via hvac → S3 sync every 60s
SHUTDOWN: seal → final S3 upload → stop process
CRASH:    Local Docker volume → immediate restart
```

### Unseal Key Security

OpenBao's unseal keys are protected by **3-factor physical separation**:

| Factor                                  | Storage                   | Compromise alone = insufficient    |
| --------------------------------------- | ------------------------- | ---------------------------------- |
| **Encrypted data** (OpenBao barrier)    | Docker volume + S3        | Unreadable without unseal key      |
| **Unseal keys** (AES-256-GCM encrypted) | S3 only                   | Undecryptable without bootstrap key |
| **ADMIN_BOOTSTRAP_KEY**                 | Environment variable only | Useless without encrypted keys     |

**Invariants**: unseal keys are **never** in cleartext on disk — memory-only during runtime. A crash automatically wipes the keys.

**Security Roadmap**:

| Version              | Approach                                                                                                    |
| -------------------- | ----------------------------------------------------------------------------------------------------------- |
| **v0.4.7** (current) | Keys on S3 encrypted AES-256-GCM+AAD, memory-only at runtime — 60 findings audited (28 fixed, 13 residual documented) |
| **v1.0**             | Transit Auto-Unseal via dedicated OpenBao (Cloud Temple KMS)                                                |
| **v2.0**             | **HSM connection** (Hardware Security Module) Cloud Temple — keys never leave the certified hardware module  |

> 📖 See [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 and §11 for full details.

---

## 📋 Tests (~600 tests, zero mocking)

> 📖 See [tests/README.md](tests/README.md) for the complete execution guide.

```bash
# 1. CLI tests — parsing + display (197 tests, NO server)
python tests/test_cli_all.py

# 2. CLI LIVE tests — full cycle (79 tests, real server)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. E2e MCP tests (312 tests, in Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Crypto tests (18 tests, NO server — AES-256-GCM + AAD + entropy validation)
python tests/test_crypto.py

# Single CLI group
python tests/test_cli_all.py --only policy

# Single e2e group
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### E2e Coverage (312 tests, 15 categories)

| Category               | Tests  | Description                                                                       |
| ---------------------- | ------ | --------------------------------------------------------------------------------- |
| System                 | 7      | health, about, services, tools_count (24)                                         |
| Vault CRUD             | 28     | create + metadata, list, info + owner, update, delete, confirm, errors            |
| Secrets CRUD           | 24     | 10 types written, read/list/delete, validation                                    |
| Versioning             | 8      | v1→v2→v3, read latest, read specific                                              |
| Passwords              | 14     | lengths, options, exclusions, CSPRNG                                              |
| Isolation              | 7      | secrets isolated between vaults                                                   |
| Errors                 | 10     | edge cases, non-existent vault, invalid type, `_vault_meta` protection            |
| S3 Sync                | 3      | tar.gz archive on S3                                                              |
| SSH CA                 | 33     | setup, multiple roles, ed25519 signing, list/info roles, CA isolation, cleanup    |
| Types                  | 14     | 14 types verified individually                                                    |
| Admin API              | 15     | health, whoami, generate-password, logs, CSPRNG uniqueness                        |
| Policies MCP           | 43     | CRUD, validation, wildcards, path_rules, duplicates, errors, Admin API REST       |
| **Policy Enforcement** | **37** | check_policy, token_update, denied/allowed, policy change, Admin API              |
| **Audit Log**          | **31** | audit_log MCP, filters (category/tool/status/since/limit), stats, Admin API /audit |
| **WAF Security**       | **17** | LFI, SQLi, XSS, RCE, Scanner Detection → 403 + legitimate request non-regression |

---

## 📁 Project Structure

```
mcp-vault/
├── .env.example              # Configuration (copy to .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Python dependencies
├── requirements.lock         # Pinned dependencies (exact versions)
├── VERSION                   # 0.4.7
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Detailed specification (v0.2.2-draft)
│   ├── TECHNICAL.md          # Technical documentation (v0.4.7)
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
│   ├── server.py             # FastMCP + 24 MCP tools + lifecycle + audit
│   ├── lifecycle.py          # Startup/shutdown orchestrator
│   ├── s3_client.py          # Hybrid S3 client SigV2/SigV4
│   ├── s3_sync.py            # File backend ↔ S3 sync
│   ├── auth/                 # Bearer tokens, check_access, ContextVar
│   ├── admin/                # Web console /admin + REST API
│   ├── openbao/              # Process manager, HCL config, lifecycle
│   ├── vault/                # Spaces, secrets, SSH CA, types
│   └── static/               # Admin SPA console (100% CLI parity)
│       ├── admin.html        # HTML structure + 7 modals
│       ├── css/admin.css     # Cloud Temple design (dark theme)
│       ├── js/               # 8 JS modules (config, api, app, dashboard, vaults, tokens, policies, activity)
│       └── img/              # logo-cloudtemple.svg
├── tests/
│   ├── README.md             # Test execution guide (auditors)
│   ├── TEST_CATALOG.md       # Test catalog for auditors
│   ├── test_cli_all.py       # 197 CLI parsing tests (no server)
│   ├── test_cli_live.py      # 79 live CLI tests (real server)
│   ├── test_e2e.py           # 312 MCP e2e tests (15 categories)
│   ├── test_crypto.py        # 18 AES-256-GCM + AAD tests
│   ├── test_service.py       # 78 low-level tests
│   ├── test_integration.py   # Pytest tests
│   └── cli/                  # CLI tests split by group (7 files)
└── waf/                      # WAF Caddy + Coraza (OWASP CRS v4)
    ├── Dockerfile            # Multi-stage (xcaddy + CRS v4.7.0)
    ├── Caddyfile             # Reverse proxy + coraza_waf
    └── coraza.conf           # Coraza config + MCP exceptions
```

---

## 🌐 Cloud Temple MCP Ecosystem

| Server           | Role                              | Port  |
| ---------------- | --------------------------------- | ----- |
| **MCP Tools**    | Toolkit (SSH, HTTP, shell)        | :8010 |
| **Live Memory**  | Shared working memory             | :8002 |
| **Graph Memory** | Long-term memory (knowledge graph) | :8080 |
| **MCP Vault**    | 🔐 Secrets vault                 | :8030 |
| **MCP Agent**    | Autonomous agent runtime          | :8040 |
| **MCP Mission**  | Mission orchestrator              | :8020 |

---

**License**: Apache 2.0 | **Author**: Cloud Temple | **Version**: 0.4.7
