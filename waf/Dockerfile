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
# SÉCURITÉ V2-12 : image pinnée par digest
FROM caddy:2-builder@sha256:84dfc3479309c690643ada9279b3e0b4352ce56b0ec8fd802c668f42b546e98f AS builder

# SÉCURITÉ V2-16 : plugins pinnés en version exacte
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2@v2.2.0 \
    --with github.com/mholt/caddy-ratelimit@v0.1.0

# ── Stage 2 : Télécharger OWASP CoreRuleSet v4 ───────────────────
# SÉCURITÉ V2-12 : image pinnée par digest (plus de tag "latest")
FROM alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 AS crs-downloader

ARG CRS_VERSION=4.7.0

RUN apk add --no-cache wget tar && \
    mkdir -p /opt/crs && \
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
         -O /tmp/crs.tar.gz && \
    tar xzf /tmp/crs.tar.gz -C /opt/crs --strip-components=1 && \
    cp /opt/crs/crs-setup.conf.example /opt/crs/crs-setup.conf && \
    rm /tmp/crs.tar.gz

# ── Stage 3 : Image finale ────────────────────────────────────────
# SÉCURITÉ V2-12 : image pinnée par digest
FROM caddy:2-alpine@sha256:fce4f15aad23222c0ac78a1220adf63bae7b94355d5ea28eee53910624acedfa

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
