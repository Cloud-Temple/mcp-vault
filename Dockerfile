# ============================================================================
# Dockerfile — MCP Vault (Python + OpenBao embedded)
# ============================================================================
# Build :  docker compose build
# Run   :  docker compose up -d
# ============================================================================

# --- Stage 1 : Download OpenBao binary ---
# SÉCURITÉ V2-12 : images pinnées par digest (pas par tag mutable)
FROM alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 AS openbao-download
ARG OPENBAO_VERSION=2.5.1
ARG TARGETARCH
RUN apk add --no-cache wget && \
    ARCH=$(case ${TARGETARCH} in arm64) echo "arm64" ;; *) echo "x86_64" ;; esac) && \
    URL="https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_Linux_${ARCH}.tar.gz" && \
    echo "Downloading OpenBao ${OPENBAO_VERSION} for ${ARCH} from ${URL}" && \
    wget -q "${URL}" -O /tmp/openbao.tar.gz && \
    mkdir -p /tmp/openbao && \
    tar xzf /tmp/openbao.tar.gz -C /tmp/openbao && \
    chmod +x /tmp/openbao/bao

# --- Stage 2 : Python application (production) ---
# SÉCURITÉ V2-12 : image pinnée par digest
FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4 AS production

# Metadata
LABEL maintainer="Cloud Temple" \
      description="MCP Vault — Secure secrets management for AI agents" \
      version="0.13.0"

# System deps for OpenBao
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy OpenBao binary from stage 1
COPY --from=openbao-download /tmp/openbao/bao /usr/local/bin/bao
RUN setcap cap_ipc_lock=+ep /usr/local/bin/bao || true

# Create openbao directories
RUN mkdir -p /openbao/file /openbao/config /openbao/logs && \
    chmod -R 700 /openbao

# Working directory
WORKDIR /app

# Install Python dependencies — LE VERROU FAIT FOI (issue #125)
# `requirements.txt` déclare des CONTRAINTES, pas des versions résolues : des
# planchers pour la plupart, plus une borne haute sur `mcp` et une égalité
# stricte sur `uvicorn`. Une construction fraîche y résout donc la dernière
# version publiée en amont qui les satisfait. Quand `mcp 2.0.0` est sorti — sans
# `mcp.server.fastmcp`, importé par server.py — toute image reconstruite a cessé
# de démarrer, sur TOUTES les versions depuis la v0.4.5. Le verrou existait déjà
# mais n'était pas consommé ici.
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Garde de CONSTRUCTION (issue #125) : l'import qui a cassé la production est
# vérifié ici, à la construction. Une résolution de dépendances incompatible
# fait désormais échouer le `build` — elle ne se découvre plus au démarrage du
# conteneur, en aval de la chaîne de livraison.
RUN python -c "from mcp.server.fastmcp import FastMCP"

# Python path pour les imports
ENV PYTHONPATH=/app/src

# Copy source code + config (P2-8 : tests/scripts exclus de l'image prod)
COPY src/ ./src/
COPY VERSION ./

# Create non-root user (after creating dirs)
RUN useradd -r -s /bin/false mcp && \
    chown -R mcp:mcp /app /openbao
USER mcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8030/health || exit 1

# Expose MCP port (internal only — WAF handles external)
EXPOSE 8030

# Start the MCP server
CMD ["python", "-m", "mcp_vault"]

# ============================================================================
# Stage 3 : Image de test (P2-8 — tests hors image prod)
# Usage : docker compose run --rm test
# ============================================================================
FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4 AS test

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=openbao-download /tmp/openbao/bao /usr/local/bin/bao
RUN mkdir -p /openbao/file /openbao/config /openbao/logs && chmod -R 700 /openbao

WORKDIR /app
# Le verrou fait foi ici AUSSI (issue #125), mais il ne contient que les
# dépendances d'EXÉCUTION : `pytest` et `pytest-asyncio` n'y figurent pas. Les
# deux fichiers sont donc passés à UNE SEULE invocation pip, qui résout leur
# intersection : les versions verrouillées l'emportent partout où le verrou
# épingle, et `requirements.txt` n'apporte que ce qui manque (les outils de
# test). Un futur verrou qui passerait SOUS un plancher déclaré ferait échouer
# la résolution, donc le build — bruyamment, et non en production.
COPY requirements.lock requirements.txt ./
RUN pip install --no-cache-dir -r requirements.lock -r requirements.txt
RUN python -c "from mcp.server.fastmcp import FastMCP"

ENV PYTHONPATH=/app/src
COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY pytest.ini ./
COPY VERSION ./
# Fixtures des tests de contrat de configuration (tests/test_env_example_contract.py) :
# le contrat dotenv publié, la documentation qui en dérive, et les artefacts de
# release dont ces tests vérifient la cohérence (LABEL du Dockerfile vs VERSION,
# section CHANGELOG de la version courante). Sans eux, ces tests échoueraient en
# conteneur — les rendre « skippables » masquerait au contraire la régression.
COPY .env.example ./
COPY DESIGN/ ./DESIGN/
COPY CHANGELOG.md ./
COPY Dockerfile ./
COPY .dockerignore ./
COPY README.md README.en.md ./
# `docker-compose.yml` est une FIXTURE de test, pas une dépendance d'exécution :
# `test_s3_bounds_shutdown_110.py` vérifie que le `stop_grace_period` couvre la
# séquence d'arrêt (#110). Sans ce COPY, ce test échouait dans l'image sur un
# `open()` manquant — bruyamment, mais invisible tant qu'aucune CI n'y exécutait
# la suite (#113).
COPY docker-compose.yml ./

RUN useradd -r -s /bin/false mcp && chown -R mcp:mcp /app /openbao
USER mcp

ENTRYPOINT ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
