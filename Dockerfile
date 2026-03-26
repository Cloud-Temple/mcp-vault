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
      version="0.4.5"

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

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH=/app/src
COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY pytest.ini ./
COPY VERSION ./

RUN useradd -r -s /bin/false mcp && chown -R mcp:mcp /app /openbao
USER mcp

ENTRYPOINT ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
