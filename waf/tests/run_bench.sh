#!/usr/bin/env bash
# Banc du WAF réel (#118) — construit l'image waf/, la démarre devant
#   (a) un backend factice qui journalise ce qu'il reçoit (HTTP/1.1 et HTTP/2),
#   (b) l'image de production mcp-vault en mode dégradé (S3 injoignable),
# puis exécute waf/tests/ avec pytest. Tout est détruit en sortie.
#
# Usage : waf/tests/run_bench.sh [arguments pytest…]
#   APP_IMAGE=<tag>    réutilise une image de production déjà construite
#   WAF_CADDYFILE=…    monte ce Caddyfile à la place de celui de l'image
#   WAF_CORAZA_CONF=…  monte ce coraza.conf à la place de celui de l'image
# Les deux dernières variables servent aux preuves par mutation
# (waf/tests/mutations.py) ; le banc nominal teste l'image telle que livrée.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SUFFIX="${BENCH_SUFFIX:-$$}"
NET_STUB="wafbench-stub-$SUFFIX"
NET_APP="wafbench-app-$SUFFIX"
WAF_IMAGE="mcp-vault-waf:bench"
APP_IMAGE="${APP_IMAGE:-}"
PORT_STUB_WAF="${PORT_STUB_WAF:-18085}"
PORT_APP_WAF="${PORT_APP_WAF:-18087}"
PORT_TLS_WAF="${PORT_TLS_WAF:-18088}"
PORT_STUB="${PORT_STUB:-18031}"
WORK="$(mktemp -d)"

cleanup() {
  for c in stub app waf-stub waf-app waf-tls; do
    if [ "${BENCH_KEEP_LOGS:-0}" = 1 ]; then
      echo "── journal $c-$SUFFIX ──"; docker logs "wafbench-$c-$SUFFIX" 2>&1 | tail -20 || true
    fi
    docker rm -f "wafbench-$c-$SUFFIX" >/dev/null 2>&1 || true
  done
  docker network rm "$NET_STUB" "$NET_APP" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker build -q -t "$WAF_IMAGE" "$ROOT/waf" >/dev/null
if [ -z "$APP_IMAGE" ]; then
  APP_IMAGE="mcp-vault:bench"
  docker build -q --target production -t "$APP_IMAGE" "$ROOT" >/dev/null
fi

docker network create "$NET_STUB" >/dev/null
docker network create "$NET_APP" >/dev/null

mounts=()
if [ -n "${WAF_CADDYFILE:-}" ]; then mounts+=(-v "$WAF_CADDYFILE:/etc/caddy/Caddyfile:ro"); fi
if [ -n "${WAF_CORAZA_CONF:-}" ]; then mounts+=(-v "$WAF_CORAZA_CONF:/etc/coraza/coraza.conf:ro"); fi

# Le factice tourne sur l'interpréteur de l'image de production (déjà épinglée
# par digest) : aucune image supplémentaire n'est tirée.
docker run -d --name "wafbench-stub-$SUFFIX" --network "$NET_STUB" --network-alias mcp-vault \
  -p "127.0.0.1:$PORT_STUB:8030" -v "$ROOT/waf/tests/stub_backend.py:/stub.py:ro" \
  --entrypoint python "$APP_IMAGE" /stub.py >/dev/null

key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker run -d --name "wafbench-app-$SUFFIX" --network "$NET_APP" --network-alias mcp-vault \
  -e ADMIN_BOOTSTRAP_KEY="$key" \
  -e S3_ENDPOINT_URL=http://127.0.0.1:1 \
  -e S3_ACCESS_KEY_ID=ci -e S3_SECRET_ACCESS_KEY=ci -e S3_BUCKET_NAME=ci \
  "$APP_IMAGE" >/dev/null

docker run -d --name "wafbench-waf-stub-$SUFFIX" --network "$NET_STUB" \
  -p "127.0.0.1:$PORT_STUB_WAF:8085" ${mounts[@]+"${mounts[@]}"} "$WAF_IMAGE" >/dev/null
docker run -d --name "wafbench-waf-app-$SUFFIX" --network "$NET_APP" \
  -p "127.0.0.1:$PORT_APP_WAF:8085" ${mounts[@]+"${mounts[@]}"} "$WAF_IMAGE" >/dev/null
docker run -d --name "wafbench-waf-tls-$SUFFIX" --network "$NET_STUB" \
  -e SITE_ADDRESS="localhost:8085" -e WAF_TLS_DIRECTIVE="tls internal" \
  -p "127.0.0.1:$PORT_TLS_WAF:8085" ${mounts[@]+"${mounts[@]}"} "$WAF_IMAGE" >/dev/null

# Configuration effectivement chargée, pour les assertions de structure.
caddyfile_src="/etc/caddy/Caddyfile"
docker run --rm ${mounts[@]+"${mounts[@]}"} "$WAF_IMAGE" \
  caddy adapt --config "$caddyfile_src" --adapter caddyfile 2>/dev/null > "$WORK/adapted.json"

# Attend une réponse 2xx. `curl -f` est indispensable : sans lui, un 502 du WAF
# (backend pas encore démarré) passait pour « prêt », et les tests partaient
# contre une application absente — constaté en CI.
wait_for() {
  for _ in $(seq 90); do
    if curl -skf -o /dev/null "$1"; then return 0; fi
    sleep 2
  done
  echo "::error::$1 ne répond pas en 2xx"; exit 1
}
wait_for "http://127.0.0.1:$PORT_STUB/__stub/log"
wait_for "http://127.0.0.1:$PORT_STUB_WAF/healthz"
wait_for "http://127.0.0.1:$PORT_APP_WAF/healthz"
wait_for "https://localhost:$PORT_TLS_WAF/healthz"

export MCP_VAULT_WAF_URL="http://127.0.0.1:$PORT_STUB_WAF"
export MCP_VAULT_WAF_STUB_URL="http://127.0.0.1:$PORT_STUB"
export MCP_VAULT_WAF_APP_URL="http://127.0.0.1:$PORT_APP_WAF"
export MCP_VAULT_WAF_TLS_URL="https://localhost:$PORT_TLS_WAF"
export MCP_VAULT_WAF_ADAPTED="$WORK/adapted.json"
export MCP_VAULT_WAF_APP_TOKEN="$key"
export MCP_VAULT_WAF_APP_CONTAINER="wafbench-app-$SUFFIX"

cd "$ROOT"
python3 -m pytest -p no:cacheprovider -c /dev/null --rootdir "$ROOT/waf/tests" "$ROOT/waf/tests" "$@"
