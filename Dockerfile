# ============================================================================
# Dockerfile — MCP Vault (Python + OpenBao embedded)
# ============================================================================
# Build :  docker compose build
# Run   :  docker compose up -d
# ============================================================================

# --- Stage 1 : Download OpenBao binary ---
# SÉCURITÉ V2-12 : images pinnées par digest (pas par tag mutable)
FROM --platform=$BUILDPLATFORM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2 AS openbao-download
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) checksum=9df0ae1f5e15c8b5ad0a61be930c7d0e5d3e507ce9cbd912c161463f5130e644 ;; \
      arm64) checksum=5eda3fd7cff9d7e4e1cc21525b9919ecc59ffd69f66f7c391deca4f106734525 ;; \
      *) echo "Architecture OpenBao non prise en charge : $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -q "https://github.com/openbao/openbao/releases/download/v2.6.6/openbao_2.6.6_linux_${TARGETARCH}.tar.gz" -O /tmp/bao.tar.gz; \
    echo "$checksum  /tmp/bao.tar.gz" | sha256sum -c -; \
    mkdir -p /tmp/openbao; \
    tar -xzf /tmp/bao.tar.gz -C /tmp/openbao bao; \
    chmod +x /tmp/openbao/bao

# --- Stage 2 : Python application (production) ---
# SÉCURITÉ V2-12 : image pinnée par digest
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS production

# Metadata
LABEL maintainer="Cloud Temple" \
      description="MCP Vault — Secure secrets management for AI agents" \
      version="0.25.0"

# System deps for OpenBao
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get -y --no-install-recommends upgrade && apt-get install -y --no-install-recommends \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy OpenBao binary from stage 1
COPY --from=openbao-download /tmp/openbao/bao /usr/local/bin/bao

# Create openbao directories
RUN mkdir -p /openbao/file /openbao/config /openbao/logs && \
    chmod -R 700 /openbao

# Working directory
WORKDIR /app

# Install Python dependencies — LE VERROU FAIT FOI (issue #125)
# `requirements.txt` déclare des CONTRAINTES, pas des versions résolues : des
# planchers pour la plupart, plus des bornes de majeur sur `mcp` et une égalité
# stricte sur `uvicorn`. Une construction fraîche y résout donc la dernière
# version publiée en amont qui les satisfait. Le verrou empêche qu'une publication
# amont change silencieusement le SDK livré.
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Garde de CONSTRUCTION (issue #125) : l'import public du serveur réellement livré est
# vérifié ici, à la construction. Une résolution de dépendances incompatible
# fait désormais échouer le `build` — elle ne se découvre plus au démarrage du
# conteneur, en aval de la chaîne de livraison.
RUN python -c "from mcp.server import MCPServer"

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

# Outil ponctuel séparé ; ni scripts ni client PG ajoutés à production.
FROM production AS pg-operator
USER root
# Le métapaquet trixie sélectionne 17, dont le restore ne cible pas PG16.
RUN install -d /usr/share/postgresql-common/pgdg && \
    curl --fail --silent --show-error https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc && \
    . /etc/os-release && \
    printf 'Types: deb\nURIs: https://apt.postgresql.org/pub/repos/apt\nSuites: %s-pgdg\nArchitectures: %s\nComponents: main\nSigned-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc\n' \
      "$VERSION_CODENAME" "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/pgdg.sources && \
    apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 && \
    dpkg-query -W postgresql-client-16 libpq5 && \
    /usr/lib/postgresql/16/bin/pg_dump --version && \
    /usr/lib/postgresql/16/bin/pg_restore --version && \
    python -c "from psycopg import pq; print('Python libpq:', pq.version())" && \
    rm -rf /var/lib/apt/lists/*
ENV PATH="/usr/lib/postgresql/16/bin:${PATH}"
COPY scripts/ ./scripts/
USER mcp
HEALTHCHECK NONE
ENTRYPOINT ["python", "/app/scripts/standalone_pg.py"]

# ============================================================================
# Stage 3 : Image de test (P2-8 — tests hors image prod)
# Usage : docker compose run --rm test
# ============================================================================
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS test

RUN apt-get -o APT::Update::Error-Mode=any update && apt-get -y --no-install-recommends upgrade && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
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
RUN python -c "from mcp.server import MCPServer"

ENV PYTHONPATH=/app/src
# Les tests contre un OpenBao réel (`bao server -dev`, ex. PKI #206) ÉCHOUENT au
# lieu de sauter si `bao`, `openssl` ou le vrai `hvac` manquent : en CI, un
# vert ne doit jamais venir d'un test qui n'a rien exercé.
ENV MCP_VAULT_TEST_BAO_REQUIRED=1
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
COPY docker-compose.postgres.yml ./

RUN useradd -r -s /bin/false mcp && chown -R mcp:mcp /app /openbao
USER mcp

ENTRYPOINT ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
