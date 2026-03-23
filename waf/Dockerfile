# WAF — Caddy + Coraza OWASP CRS
#
# Build multi-stage :
#   1. Compiler Caddy avec le plugin coraza-caddy v2 via xcaddy
#   2. Télécharger les règles OWASP CoreRuleSet v4
#   3. Image finale minimale Alpine
#
# Sécurité : le WAF protège l'API MCP contre les attaques L7
# (injections SQL, XSS, SSRF, path traversal, etc.)

# ── Stage 1 : Build Caddy avec Coraza ─────────────────────────────
FROM caddy:2-builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

# ── Stage 2 : Télécharger OWASP CoreRuleSet v4 ───────────────────
FROM alpine:latest AS crs-downloader

ARG CRS_VERSION=4.7.0

RUN apk add --no-cache wget tar && \
    mkdir -p /opt/crs && \
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
         -O /tmp/crs.tar.gz && \
    tar xzf /tmp/crs.tar.gz -C /opt/crs --strip-components=1 && \
    cp /opt/crs/crs-setup.conf.example /opt/crs/crs-setup.conf && \
    rm /tmp/crs.tar.gz

# ── Stage 3 : Image finale ────────────────────────────────────────
FROM caddy:2-alpine

# Copier le binaire Caddy compilé avec Coraza
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Copier les règles OWASP CRS
COPY --from=crs-downloader /opt/crs /opt/crs

# Créer les répertoires nécessaires
RUN mkdir -p /var/log/coraza /etc/coraza

# Copier la configuration
COPY Caddyfile /etc/caddy/Caddyfile
COPY coraza.conf /etc/coraza/coraza.conf

EXPOSE 8085
