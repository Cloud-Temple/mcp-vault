# ============================================================================
# Dockerfile — MCP Vault (Python + OpenBao embedded)
# ============================================================================
# Build :  docker compose build
# Run   :  docker compose up -d
# ============================================================================

# --- Stage 1 : Download OpenBao binary ---
FROM alpine:3.20 AS openbao-download
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

# --- Stage 2 : Python application ---
FROM python:3.12-slim

# Metadata
LABEL maintainer="Cloud Temple" \
      description="MCP Vault — Secure secrets management for AI agents" \
      version="0.1.0"

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

# Copy source code + tests + scripts + config
COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY pytest.ini ./
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
