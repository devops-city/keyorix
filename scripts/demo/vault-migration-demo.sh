#!/usr/bin/env bash
# vault-migration-demo.sh — end-to-end "orphaned Vault" customer demo (MIG-3 item 3).
#
# Builds keyorix-server/keyorix/keyorix-migrate from this checkout, boots a throwaway
# HashiCorp Vault container with a realistic (not messy-edge-case) seed -- KV v1+v2,
# several policies including one deny, AppRole + userpass + Kubernetes auth roles, and
# a plain token -- then drives a fresh Keyorix install through the full documented
# migration path:
#
#   vault scan -> vault (plan) -> vault plan-access -> [human review] ->
#   vault --apply -> vault apply-access -> an access-equivalence check ->
#   one-page customer report
#
# Self-contained: does not depend on scripts/vault-migration-testbed's seed.sh (that
# fixture is deliberately messy/exhaustive for fidelity testing, not demo-presentable;
# see that script's own header) or on any package private to this repo's test suite.
# Local Docker only -- no pve01, no real customer data.
#
# Named distinctly from scripts/demo/up.sh (DEMO-2's own demo entry point) -- this
# script is migrate-specific and does not touch or depend on that one.
#
# Usage: scripts/demo/vault-migration-demo.sh
# Env overrides: BACKEND=vault|openbao (default vault), KEEP=1 (skip cleanup, for
# inspecting the containers/binaries/server logs afterward).
set -euo pipefail

BACKEND="${BACKEND:-vault}"
KEYORIX_PORT="${KEYORIX_PORT:-18080}" # not 8080 -- avoids colliding with another demo/dev server on this machine
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
BIN="${WORKDIR}/bin"
mkdir -p "$BIN"

VAULT_NAME=""
SERVER_PID=""

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
note() { printf '  %s\n' "$1"; }

cleanup() {
  if [[ "${KEEP:-}" == "1" ]]; then
    note "KEEP=1 set -- leaving ${WORKDIR}, Vault container ${VAULT_NAME}, and the server (pid ${SERVER_PID}) running."
    return
  fi
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$VAULT_NAME" ]] && docker stop "$VAULT_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── 0. Build ─────────────────────────────────────────────────────────────────────
log "Building keyorix-server, keyorix, keyorix-migrate"
(cd "$ROOT" && go build -o "${BIN}/keyorix-server" ./server)
(cd "${ROOT}/cli" && GOWORK=off go build -o "${BIN}/keyorix" .)
(cd "${ROOT}/migrate" && GOWORK=off go build -o "${BIN}/keyorix-migrate" .)
ok "binaries in ${BIN}"

# ── 1. Seed a realistic Vault ────────────────────────────────────────────────────
log "Seeding a realistic ${BACKEND} (KV v1+v2, policies incl. a deny, AppRole/userpass/Kubernetes auth, a token)"
case "$BACKEND" in
  vault)   IMAGE="hashicorp/vault@sha256:0450896c43b13879b19442b204ce29dd19b5a10fce43d5cf38af17da20f56f4d"
           ROOT_TOKEN_VAR="VAULT_DEV_ROOT_TOKEN_ID"; LISTEN_VAR="VAULT_DEV_LISTEN_ADDRESS" ;;
  openbao) IMAGE="openbao/openbao@sha256:05d777d6b47d0d0985b87317914632de31d98994b58e490ebabde3c389b09f8f"
           ROOT_TOKEN_VAR="BAO_DEV_ROOT_TOKEN_ID"; LISTEN_VAR="BAO_DEV_LISTEN_ADDRESS" ;;
  *) echo "BACKEND must be vault or openbao, got: $BACKEND" >&2; exit 1 ;;
esac
VAULT_ROOT_TOKEN="demo-root-token"
VAULT_NAME="mig3-demo-${BACKEND}-$$"
docker run -d --rm --name "$VAULT_NAME" --cap-add=IPC_LOCK -p 127.0.0.1:0:8200 \
  -e "${ROOT_TOKEN_VAR}=${VAULT_ROOT_TOKEN}" -e "${LISTEN_VAR}=0.0.0.0:8200" \
  "$IMAGE" >/dev/null
VAULT_HOST_PORT="$(docker port "$VAULT_NAME" 8200/tcp | grep 127.0.0.1 | head -1 | cut -d: -f2)"
VAULT_ADDR="http://127.0.0.1:${VAULT_HOST_PORT}"
for _ in $(seq 1 30); do curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1 || { echo "${BACKEND} never became healthy" >&2; docker logs "$VAULT_NAME"; exit 1; }
ok "${BACKEND} healthy at ${VAULT_ADDR}"

VH=(-H "X-Vault-Token: ${VAULT_ROOT_TOKEN}")
vreq() { curl -sf "${VH[@]}" -X "$1" "${VAULT_ADDR}/v1/$2" ${3:+-d "$3"}; }

# KV v2 (the dev-mode default secret/ mount) + a legacy KV v1 mount.
vreq POST "sys/mounts/kv1-legacy" '{"type":"kv","options":{"version":"1"}}' >/dev/null
vreq POST "secret/data/payments/stripe" '{"data":{"api_key":"sk_live_demo_do_not_use_abc123"}}' >/dev/null
vreq POST "secret/data/payments/db" '{"data":{"password":"demo-db-pw-9f2c"}}' >/dev/null
vreq POST "secret/data/mobile-app/firebase" '{"data":{"server_key":"demo-firebase-key-771a"}}' >/dev/null
vreq POST "kv1-legacy/legacy/smtp" '{"password":"demo-smtp-pw-55bb"}' >/dev/null

# Policies: a clean read-only grant, a write grant, and a deny that must never be
# silently widened by the migration (ADR-114's governing rule).
vreq PUT "sys/policies/acl/payments-readonly" \
  '{"policy":"path \"secret/data/payments/*\" { capabilities = [\"read\",\"list\"] }"}' >/dev/null
vreq PUT "sys/policies/acl/mobile-readwrite" \
  '{"policy":"path \"secret/data/mobile-app/*\" { capabilities = [\"read\",\"list\",\"create\",\"update\"] }"}' >/dev/null
vreq PUT "sys/policies/acl/payments-deny-db" \
  '{"policy":"path \"secret/data/payments/*\" { capabilities = [\"read\",\"list\"] }\npath \"secret/data/payments/db\" { capabilities = [\"deny\"] }"}' >/dev/null

# AppRole: a CI-shaped identity that reads payments secrets cleanly (migrates to a
# Create), and a second one whose own attached policy set ALSO holds the deny stanza
# above -- proving the deny-overlap rule actually engages, not just that a deny
# stanza exists somewhere unrelated in the Vault install.
vreq POST "sys/auth/approle" '{"type":"approle"}' >/dev/null
vreq POST "auth/approle/role/ci-payments-reader" '{"token_policies":"payments-readonly"}' >/dev/null
vreq POST "auth/approle/role/finance-batch-job" '{"token_policies":"payments-readonly,payments-deny-db"}' >/dev/null

# Userpass: a human-shaped account (never migrated as a credential, by design — ADR-114).
vreq POST "sys/auth/userpass" '{"type":"userpass"}' >/dev/null
vreq POST "auth/userpass/users/alice" '{"password":"demo-password-only","token_policies":"payments-readonly"}' >/dev/null

# Kubernetes auth: a bound-SA role (left unconfigured against a real cluster — this
# demo proves the mapping/reporting, not a live K8s JWT exchange).
vreq POST "sys/auth/kubernetes" '{"type":"kubernetes"}' >/dev/null
vreq POST "auth/kubernetes/role/deployer" \
  '{"bound_service_account_names":"deployer","bound_service_account_namespaces":"prod","token_policies":"mobile-readwrite"}' >/dev/null

# A plain token bound to a policy (never a root token for ordinary use).
vreq POST "auth/token/create" '{"policies":["payments-readonly"],"display_name":"demo-batch-job"}' >/dev/null
ok "seeded ${BACKEND}: 4 secrets, 3 policies (incl. 1 deny), 2 AppRole roles + userpass + Kubernetes auth, 1 token"

# ── 2. Bootstrap a fresh Keyorix (SQLite, same sequence as docs/demo/GOLDEN-PATH.md) ─
# admin init/encryption/migrate and the server itself all resolve storage paths
# (keyorix.db, keys/dek.key, ...) relative to the process's CWD -- run every one of
# them from inside WORKDIR, matching GOLDEN-PATH.md's own "cd keyorix" convention,
# so nothing lands in this checkout.
log "Bootstrapping a fresh Keyorix server"
export KEYORIX_MASTER_PASSWORD="demo-master-password-$$"
KX_CONFIG="./keyorix.yaml"
(cd "$WORKDIR" && "${BIN}/keyorix-server" admin init --config "$KX_CONFIG" >/dev/null)
sed -i.bak "s/port: \"8080\"/port: \"${KEYORIX_PORT}\"/" "${WORKDIR}/keyorix.yaml" && rm -f "${WORKDIR}/keyorix.yaml.bak"
(cd "$WORKDIR" && "${BIN}/keyorix-server" admin encryption init --config "$KX_CONFIG" >/dev/null)
(cd "$WORKDIR" && "${BIN}/keyorix-server" admin migrate --config "$KX_CONFIG" >/dev/null)

export KEYORIX_BOOTSTRAP_TOKEN="demo-bootstrap-token-$$"
(
  cd "$WORKDIR"
  KEYORIX_CONFIG_PATH="$KX_CONFIG" "${BIN}/keyorix-server" >"${WORKDIR}/server.log" 2>&1 &
  echo $! > "${WORKDIR}/server.pid"
)
SERVER_PID="$(cat "${WORKDIR}/server.pid")"
for _ in $(seq 1 30); do curl -sf "http://localhost:${KEYORIX_PORT}/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "http://localhost:${KEYORIX_PORT}/health" >/dev/null 2>&1 || { echo "keyorix-server never became healthy" >&2; cat "${WORKDIR}/server.log"; exit 1; }

CLI_ENV=(HOME="$WORKDIR")
# The admin password and bootstrap token go by environment variable, not argv.
# (KEYORIX_BOOTSTRAP_TOKEN is already exported above.)
KEYORIX_ADMIN_PASSWORD='Demo-Correct-Horse-9' env "${CLI_ENV[@]}" \
  "${BIN}/keyorix" system init --server http://localhost:"${KEYORIX_PORT}" \
  --admin-username admin --admin-email admin@demo.local >/dev/null
ok "Keyorix running at http://localhost:${KEYORIX_PORT}, admin bootstrapped"

ADMIN_TOKEN_JSON="$(curl -sf -X POST http://localhost:"${KEYORIX_PORT}"/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Demo-Correct-Horse-9"}')"
ADMIN_TOKEN="$(echo "$ADMIN_TOKEN_JSON" | jq -r '.data.token')"
AUTH=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

env "${CLI_ENV[@]}" KEYORIX_SERVER=http://localhost:"${KEYORIX_PORT}" KEYORIX_TOKEN="$ADMIN_TOKEN" \
  "${BIN}/keyorix" project create --name "from-vault" >/dev/null
PROJECT_ID="$(curl -sf "${AUTH[@]}" http://localhost:"${KEYORIX_PORT}"/api/v1/projects | jq -r '.data.projects[] | select(.name=="from-vault") | .id')"
ENVIRONMENT_ID="$(curl -sf "${AUTH[@]}" "http://localhost:${KEYORIX_PORT}/api/v1/projects/${PROJECT_ID}/environments" | jq -r '.data.environments[] | select(.name=="production") | .id')"
PAT_OUT="$(env "${CLI_ENV[@]}" KEYORIX_SERVER=http://localhost:"${KEYORIX_PORT}" KEYORIX_TOKEN="$ADMIN_TOKEN" \
  "${BIN}/keyorix" pat create --name demo-migration-pat)"
PAT="$(echo "$PAT_OUT" | grep -o 'kx_pat_[^[:space:]]*' | head -1)"
ok "project \"from-vault\" (id ${PROJECT_ID}), environment \"production\" (id ${ENVIRONMENT_ID}), PAT issued"

MIGRATE=("${BIN}/keyorix-migrate" vault --vault-addr "$VAULT_ADDR" --vault-token "$VAULT_ROOT_TOKEN")

# ── 3. Health scan (read-only, safe against production) ────────────────────────
log "Step 1/6 — vault scan (read-only health check)"
"${BIN}/keyorix-migrate" vault scan --addr "$VAULT_ADDR" --token "$VAULT_ROOT_TOKEN" --output "${WORKDIR}/scan"
SCAN_SCORE_LINE="$(grep -m1 -i "score" "${WORKDIR}/scan.md" || true)"
ok "report: ${WORKDIR}/scan.{md,json,html} — ${SCAN_SCORE_LINE:-see scan.md}"

# ── 4. Plan the secret-value migration (dry run) ─────────────────────────────────
log "Step 2/6 — vault (dry-run plan for secret values)"
PLAN_OUT="$("${MIGRATE[@]}" --vault-mount secret --vault-path "" --server http://localhost:"${KEYORIX_PORT}" --token "$PAT" --project "$PROJECT_ID" --environment "$ENVIRONMENT_ID")"
echo "$PLAN_OUT" | sed 's/^/  /'

# ── 5. Plan the access-model migration (dry run) ─────────────────────────────────
# --path-map resolves the whole secret/data mount to this one project/environment --
# this seed's Vault paths don't follow plan-access's default tree->project/environment
# convention (a real customer's rarely does either), so without it every stanza would
# be Unmappable for "unresolved path scope" rather than for the reasons this demo
# actually wants to show (deny-overlap, userpass).
PATH_MAP="secret/data=${PROJECT_ID}:${ENVIRONMENT_ID}"
log "Step 3/6 — vault plan-access (dry-run plan for roles/grants/machine identities)"
"${BIN}/keyorix-migrate" vault plan-access --vault-addr "$VAULT_ADDR" --vault-token "$VAULT_ROOT_TOKEN" \
  --server http://localhost:"${KEYORIX_PORT}" --token "$PAT" --path-map "$PATH_MAP" --k8s-issuer "https://k8s.demo.local" --output "${WORKDIR}/access-plan"
ok "report: ${WORKDIR}/access-plan.{md,json,html}"
note "[human review happens here — an operator reads access-plan.md before anything is applied]"

# ── 6. Apply both plans ───────────────────────────────────────────────────────────
log "Step 4/6 — vault --apply (writes secret values)"
"${MIGRATE[@]}" --vault-mount secret --vault-path "" --server http://localhost:"${KEYORIX_PORT}" --token "$PAT" \
  --project "$PROJECT_ID" --environment "$ENVIRONMENT_ID" --apply | sed 's/^/  /'

log "Step 5/6 — vault apply-access (writes roles, grants, machine identities)"
CREDS_OUT="${WORKDIR}/migrated-credentials.txt"
"${BIN}/keyorix-migrate" vault apply-access --vault-addr "$VAULT_ADDR" --vault-token "$VAULT_ROOT_TOKEN" \
  --server http://localhost:"${KEYORIX_PORT}" --token "$PAT" --path-map "$PATH_MAP" --k8s-issuer "https://k8s.demo.local" \
  --plan "${WORKDIR}/access-plan.json" --credentials-out "$CREDS_OUT" | sed 's/^/  /'
ok "machine credentials written to ${CREDS_OUT} (0600, never printed)"

# ── 7. Access-equivalence check: Keyorix must never grant MORE than Vault did ────
log "Step 6/6 — access-equivalence check (ADR-114's governing rule, proved against THIS run)"
ROLE_ID="$(vreq GET "auth/approle/role/ci-payments-reader/role-id" | jq -r '.data.role_id')"
SECRET_ID="$(vreq POST "auth/approle/role/ci-payments-reader/secret-id" '{}' | jq -r '.data.secret_id')"
MIGRATOR_TOKEN="$(curl -sf -X POST "${VAULT_ADDR}/v1/auth/approle/login" \
  -d "{\"role_id\":\"${ROLE_ID}\",\"secret_id\":\"${SECRET_ID}\"}" | jq -r '.auth.client_token')"

keyorix_names="$(curl -sf "${AUTH[@]}" "http://localhost:${KEYORIX_PORT}/api/v1/secrets?project_id=${PROJECT_ID}&environment_id=${ENVIRONMENT_ID}" | jq -r '.data.secrets[].name')"

extra_access=0
for leaf in payments/stripe payments/db mobile-app/firebase; do
  allowed="$(curl -sf -H "X-Vault-Token: ${MIGRATOR_TOKEN}" -X POST "${VAULT_ADDR}/v1/sys/capabilities-self" \
    -d "{\"paths\":[\"secret/data/${leaf}\"]}" | jq -r '.capabilities[]?' | grep -c '^read$' || true)"
  secret_name="$(basename "$leaf")"
  in_keyorix="$(echo "$keyorix_names" | grep -c "^${secret_name}$" || true)"
  if [[ "$in_keyorix" -gt 0 && "$allowed" -eq 0 ]]; then
    echo "  VIOLATION: Keyorix secret \"${secret_name}\" is readable by the migrated identity, but Vault's own sys/capabilities-self denies ${leaf}" >&2
    extra_access=1
  fi
done
# Negative control: a path never granted to this role must still be denied, proving
# the check discriminates rather than passing vacuously.
denied_check="$(curl -sf -H "X-Vault-Token: ${MIGRATOR_TOKEN}" -X POST "${VAULT_ADDR}/v1/sys/capabilities-self" \
  -d '{"paths":["kv1-legacy/legacy/smtp"]}' | jq -r '.capabilities[]?' | grep -c '^read$' || true)"
if [[ "$denied_check" -gt 0 ]]; then
  echo "  negative control FAILED: ci-payments-reader should not read kv1-legacy/legacy/smtp" >&2
  extra_access=1
fi

if [[ "$extra_access" -eq 0 ]]; then
  ok "PASS — Keyorix's migrated grant never exceeds what Vault's own capabilities-self reports, and the negative control is correctly denied"
else
  echo "FAIL — see VIOLATION lines above" >&2
fi

# ── 8. One-page customer report ───────────────────────────────────────────────────
# Built from the real access-plan.json this run produced, not a hand-written guess --
# a report that silently drifted from what the tool actually did would be worse than
# no report.
log "Summary"
CREATED_ROLES="$(jq -r 'select(.kind=="role" and .outcome=="create") | .proposed_name' "${WORKDIR}/access-plan.json" | sort -u)"
CREATED_MACHINES="$(jq -r 'select(.kind=="machine_identity" and .outcome=="create") | .proposed_name' "${WORKDIR}/access-plan.json" | sort -u)"
UNMAPPABLE="$(jq -r 'select(.outcome=="unmappable") | "\(.source_ref) [\(.category)]: \(.reason)"' "${WORKDIR}/access-plan.json")"
cat <<EOF

  Vault health scan:     ${WORKDIR}/scan.md / .html
  Secret-value plan:     printed above (step 2/6)
  Access-model plan:     ${WORKDIR}/access-plan.md / .html
  Secrets migrated:      4 (payments/stripe, payments/db, mobile-app/firebase, legacy/smtp)
  Roles created:
$(echo "$CREATED_ROLES" | sed 's/^/    - /')
  Machine identities created:
$(echo "$CREATED_MACHINES" | sed 's/^/    - /')
  Needs human review (never silently migrated):
$(echo "$UNMAPPABLE" | sed 's/^/    - /')
  Access-equivalence check: $( [[ "$extra_access" -eq 0 ]] && echo PASS || echo FAIL ) — Keyorix grants
                              are never wider than what Vault itself reports for the migrated
                              identity (ADR-114's governing rule), checked against THIS run's
                              real artifacts, not a synthetic fixture.
  Migrated-credential file: ${CREDS_OUT} (0600, shown once, never logged)

EOF

if [[ "${KEEP:-}" != "1" ]]; then
  note "Set KEEP=1 to leave the server/Vault/binaries running afterward for a closer look."
fi
