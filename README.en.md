# 🔐 MCP Vault

> A secret vault for AI agents, built on OpenBao and exposed through the Model Context Protocol (MCP).

> 🇫🇷 [Version française](README.md)

MCP Vault centralizes the secrets, access policies, and temporary credentials required by AI agents. It embeds [OpenBao](https://openbao.org/) for encryption and storage, adds an authenticated and policy-controlled MCP API, and provides an administration console and CLI.

**Version**: 0.20.1 · **License**: [Apache-2.0](LICENSE)

> [!IMPORTANT]
> MCP Vault is a security component intended for controlled environments. Read the [security model](#security-model) and [security audit](DESIGN/mcp-vault/SECURITY_AUDIT.md) before using it in production.

## Administration console

| Dashboard | Vaults and secrets | Audit and alerts |
| :---: | :---: | :---: |
| ![MCP Vault dashboard](screenshoots/screen1.png) | ![Vault and secret management](screenshoots/screen2.png) | ![Audit and alerts](screenshoots/screen3.png) |

## Features

- Isolated vaults and versioned secrets using OpenBao KV v2.
- Bearer authentication required by default, with policies by tool, vault, and path.
- Optional Mission JWT mode with token validation, local bindings, and fail-closed rejection.
- Temporary access through single-use wrapping, SSH certificates, and an internal PKI.
- Web console, CLI, and JSONL audit log.
- Caddy/Coraza WAF included in the Docker Compose deployment.
- Local persistence with synchronization to S3-compatible storage.

## Architecture

```text
MCP client / CLI / browser
              │
              ▼
       Caddy + Coraza WAF
              │
              ▼
     MCP Vault (ASGI / MCP)
       │       │        │
       │       │        └── Authentication, policies, and audit
       │       └─────────── Administration console
       └─────────────────── Embedded OpenBao (KV, SSH, PKI)
                                  │
                                  ├── Local Docker volume
                                  └── S3 synchronization
```

The application container is not published directly by the Docker Compose configuration: traffic goes through the WAF. See [ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) for the complete architecture and operating contracts.

## Quick start

### Requirements

- Docker with the Compose plugin;
- S3-compatible storage;
- a generated administration bootstrap key stored as a secret.

### Installation

```bash
git clone https://github.com/Cloud-Temple/mcp-vault.git
cd mcp-vault
cp .env.example .env
```

Before starting the service, set at least the following values in `.env`:

- `ADMIN_BOOTSTRAP_KEY` to a strong random value meeting the requirements documented in `.env.example`;
- `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`, and `S3_REGION_NAME`;
- the allowed host names when exposing the service through your own domain.

Never commit the `.env` file.

```bash
docker compose up -d --build

# Process liveness
curl -fsS http://localhost:8085/healthz

# Vault availability and readiness
curl -fsS http://localhost:8085/health
curl -fsS http://localhost:8085/ready
```

Default entry points:

| Interface | URL | Protection |
| --- | --- | --- |
| MCP Streamable HTTP | `http://localhost:8085/mcp` | Bearer required |
| Console | `http://localhost:8085/admin` | Authenticated administration API |
| Health | `/healthz`, `/health`, `/ready` | Public responses without sensitive details |

The CLI and its local Python prerequisites are documented in
[scripts/README.md](scripts/README.md).

## MCP tools

The current version exposes **39 MCP tools**. The [canonical catalog](src/mcp_vault/tool_catalog.py) is checked automatically against the tools registered by the server.

| Domain | Count | Main capabilities |
| --- | ---: | --- |
| System | 2 | Service information and health |
| Vaults | 5 | Creation, inventory, metadata, and deletion |
| Secrets | 6 | Write, read, list, delete, types, and generation |
| JIT wrapping | 5 | Single-use delivery, consumption, status, and revocation |
| SSH | 7 | SSH CA, roles, signing, and temporary operator access |
| Policies | 4 | Create, read, list, and delete |
| Tokens | 1 | Token lifecycle |
| PKI | 8 | CA, roles, issuance, inventory, revocation, and rotation |
| Audit | 1 | Filtered audit log access |

> [!CAUTION]
> `secret_wrap_lookup` is not a read-only lookup: this compensation can **revoke** matching wraps, while some states may remain unrevoked or indeterminate. Use `secret_wrap_status` to inspect state without revoking a wrap.

## Security model

- Secrets at rest are encrypted by the OpenBao cryptographic barrier.
- Unseal material is encrypted with AES-256-GCM before being stored in S3; the bootstrap key remains separate.
- The default `bearer` mode requires a valid token. Mission JWT and dual-stack modes are available to integrations that enforce their complete contracts.
- Policies restrict accessible tools, vaults, and paths.
- Policy, Mission binding, and wrap stores reject decisions based on stale snapshots when S3 can no longer refresh them. Documented exception: the Token Store may keep authenticating its stale bearer cache, while `/health` and `/ready` report the instance as unavailable.
- The WAF filters HTTP input but does not replace network segmentation or infrastructure secret management.

### Important limitations

- **Single-instance deployment**: OpenBao is embedded and S3 synchronization is last-write-wins. MCP Vault is not an active-active cluster and must not be horizontally replicated as-is.
- **Asynchronous durability**: the local volume is the active copy; S3 provides restoration and synchronization. An abrupt shutdown can leave the latest remote copy behind.
- **Local audit**: the JSONL log lives on a local volume. It is not synchronized to S3, immutable, or WORM. Export it to your logging system when those properties are required.
- **Wrapping**: the TTL limits the delivery envelope, not the lifetime of the external credential it contains.
- **Memory and responses**: an authorized secret necessarily exists in plaintext in process memory and in the response sent to the authorized client.
- **Bootstrap key**: when presented to the service, it grants full administration access; its compromise is already a major incident. Combined with an S3 compromise, it also defeats the protection of persisted data and unseal material.

Read the [security audit](DESIGN/mcp-vault/SECURITY_AUDIT.md) for residual risks and mitigations.

## Configuration

The [`.env.example`](.env.example) file is the exhaustive, tested reference. Its main groups are:

| Group | Purpose |
| --- | --- |
| Bootstrap | Unseal material protection and initial administration |
| S3 | Persistence, restoration, and authorization stores |
| Network and WAF | Public port, allowed hosts, TLS, and HTTP filtering |
| Authentication | Opaque bearer, Mission JWT, or dual-stack transition |
| OpenBao | Embedded process, local storage, and lifecycle |
| SSH / PKI / wrapping | Temporary access and certificate authorities |
| Audit and retention | Logging and purging of revoked or expired objects |

Sensitive values must be injected at deployment time, never baked into an image or committed to Git.

## Development and tests

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Some integration suites require Docker, S3, and a running server. The [test guide](tests/README.md) documents the available levels, requirements, and targeted commands; the [E2E catalog](tests/TEST_CATALOG.md) describes the covered scenarios.

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture](DESIGN/mcp-vault/ARCHITECTURE.md) | Architecture, persistence, security, and detailed contracts |
| [Technical documentation](DESIGN/mcp-vault/TECHNICAL.md) | Modules, dependencies, deployment, and maintenance |
| [Security audit](DESIGN/mcp-vault/SECURITY_AUDIT.md) | Consolidated findings, fixes, and residual risks |
| [CLI guide](scripts/README.md) | Administration and operations commands |
| [Test guide](tests/README.md) | Local, live, and Docker test execution |
| [Changelog](CHANGELOG.md) | Version history |

## License

MCP Vault is distributed under the [Apache License 2.0](LICENSE).
