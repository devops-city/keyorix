#!/usr/bin/env bash
# "Migrate off Vault in 5 minutes" — a self-contained demo.
#
# Stands up Keyorix (docker compose) + a throwaway HashiCorp Vault, seeds Vault
# with sample secrets, then migrates EVERY secret into Keyorix with one command
# (`keyorix secret import --source vault`) and shows them. Tears everything down
# on exit.
#
# Requires: docker, curl, jq, and the `keyorix` CLI on PATH
#   (curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh)
# For testing against a locally-built CLI: KEYORIX_BIN=/path/to/keyorix ./run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/docker-compose.yml -p keyorix-demo"
KX="${KEYORIX_BIN:-keyorix}"
KEYORIX_URL="http://localhost:8088"
VAULT_PORT="8200"
VAULT_ADDR="http://localhost:${VAULT_PORT}"
VAULT_TOKEN="root"

# Throwaway demo credentials (compose bootstraps the admin from these). The stack
# reads its credentials from Docker secrets files, not the environment, so write
# them into a temp directory (0640, group = your primary group, which the
# containers join via KEYORIX_SECRETS_GID).
KEYORIX_ADMIN_PASSWORD="Admin123!"
export KEYORIX_ADMIN_USERNAME="admin"
export KEYORIX_ADMIN_EMAIL="admin@keyorix.local"
DEMO_SECRETS_DIR="$(mktemp -d)"
(
  umask 037
  printf '%s\n' "demo-db-pass" > "${DEMO_SECRETS_DIR}/db_password"
  printf '%s\n' "demo-master-pass" > "${DEMO_SECRETS_DIR}/master_password"
  printf '%s\n' "${KEYORIX_ADMIN_PASSWORD}" > "${DEMO_SECRETS_DIR}/admin_password"
  printf '%s\n' "demo-bootstrap-token-0123456789abcdef" > "${DEMO_SECRETS_DIR}/bootstrap_token"
)
export KEYORIX_SECRETS_DIR="${DEMO_SECRETS_DIR}"
KEYORIX_SECRETS_GID="$(id -g)"
export KEYORIX_SECRETS_GID

c()  { local msg="$1"; printf '\n\033[1;34m▶ %s\033[0m\n' "$msg"; }
ok() { local msg="$1"; printf '\033[0;32m✓ %s\033[0m\n' "$msg"; }

cleanup() {
  c "Cleaning up"
  docker rm -f keyorix-demo-vault >/dev/null 2>&1 || true
  $COMPOSE down -v >/dev/null 2>&1 || true
  rm -rf "${DEMO_SECRETS_DIR}"
  ok "Demo environment removed"
}
trap cleanup EXIT

command -v "$KX" >/dev/null 2>&1 || { echo "keyorix CLI not found — install it first (see header)"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

c "1/5  Starting Keyorix (Postgres + API + web UI)"
$COMPOSE up -d postgres backend web
printf 'Waiting for Keyorix to bootstrap'
TOKEN=""
set +e  # the early attempts fail while the backend boots — don't let that exit
for _ in $(seq 1 60); do
  TOKEN="$(curl -s -X POST "${KEYORIX_URL}/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${KEYORIX_ADMIN_USERNAME}\",\"password\":\"${KEYORIX_ADMIN_PASSWORD}\"}" \
    2>/dev/null | jq -r '.data.token // empty')"
  [[ -n "$TOKEN" ]] && break
  printf '.'; sleep 2
done
set -e
echo
[[ -n "$TOKEN" ]] || { echo "Keyorix did not come up in time"; $COMPOSE logs backend | tail -20; exit 1; }
ok "Keyorix is up — logged in as ${KEYORIX_ADMIN_USERNAME}"

c "2/5  Starting a throwaway HashiCorp Vault and seeding it"
docker rm -f keyorix-demo-vault >/dev/null 2>&1 || true
docker run -d --name keyorix-demo-vault -p "${VAULT_PORT}:8200" \
  -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  hashicorp/vault:latest >/dev/null
set +e
for _ in $(seq 1 30); do curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1 && break; sleep 1; done
set -e
vault_put() { local path="$1"; local data="$2"; curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" -X POST "${VAULT_ADDR}/v1/secret/data/$path" -d "$data" >/dev/null; }
vault_put demo/prod/database '{"data":{"username":"app_user","password":"REPLACE_WITH_YOUR_DB_PASSWORD"}}'
vault_put demo/prod/stripe   '{"data":{"value":"REPLACE_WITH_YOUR_STRIPE_KEY"}}'
vault_put demo/prod/redis    '{"data":{"url":"redis://cache.prod.internal:6379"}}'
ok "Seeded Vault with 3 paths under secret/demo/prod/ (4 secrets)"

c "3/5  What's in Vault today"
echo "  secret/demo/prod/database  → username, password"
echo "  secret/demo/prod/stripe    → value"
echo "  secret/demo/prod/redis     → url"

c "4/5  Migrating EVERY secret into Keyorix — one command"
echo "  \$ keyorix secret import --source vault --vault-path demo/prod --project default --env production"
KEYORIX_SERVER="$KEYORIX_URL" KEYORIX_TOKEN="$TOKEN" \
VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" \
  "$KX" secret import --source vault --vault-path demo/prod --project default --env production

c "5/5  The secrets now live in Keyorix"
KEYORIX_SERVER="$KEYORIX_URL" KEYORIX_TOKEN="$TOKEN" "$KX" secret list

ok "Migration complete. Open ${KEYORIX_URL} (admin / ${KEYORIX_ADMIN_PASSWORD}) to browse them in the UI."
echo
echo "That's the whole 'leave Vault' story: point Keyorix at your live Vault, run one"
echo "command, and every secret is imported — names, values, multi-field paths and all."
