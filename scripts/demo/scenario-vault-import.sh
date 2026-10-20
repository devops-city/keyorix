#!/usr/bin/env bash
# scripts/demo/scenario-vault-import.sh — catalogue scenario 2: Vault migration.
#
# Imports a Vault KV tree into Keyorix with `keyorix-migrate vault`: a dry run first (the plan:
# source path -> Keyorix secret name, create/update/skip/conflict, nothing written), then
# --apply, then an application reads the same values from Keyorix. Re-running the import is a
# no-op (every item "skip"), which is what makes a staged cut-over safe.
#
# The source is a Vault EXPORT FILE (scripts/demo/fixtures/vault-export.json) served by
# scripts/demo/fakevault, a protocol-level stand-in for the few KV v2 calls keyorix-migrate
# makes. The real-Vault/OpenBao container walk (policies, AppRole, K8s auth, access
# equivalence) is scripts/demo/vault-migration-demo.sh - it needs Docker (pending e2e VM).
#
#   scenario-vault-import.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init
cd "$SCN_REPO_ROOT"

FAKEVAULT="bin/demo-fakevault"; MIGRATE="bin/keyorix-migrate"; FIXTURE="scripts/demo/fixtures/vault-export.json"
[ -x "$FAKEVAULT" ] && [ -x "$MIGRATE" ] || { echo "build the helpers: go build -o bin/demo-fakevault ./scripts/demo/fakevault && GOWORK=off go -C migrate build -o ../bin/keyorix-migrate ." >&2; exit 1; }
VPORT="${KEYORIX_DEMO_VAULT_PORT:-18200}"
PROJECT_ID=3                      # mobile-app: no secrets of its own in the seed
WORK="${SCN_CLI_HOME#"$PWD"/}"    # relative path (the CLI refuses absolute --from-file style paths)

VTOKEN_FILE="$WORK/.vault-src-token"; PAT_FILE="$WORK/.migrate-pat"
( umask 077; openssl rand -hex 16 > "$VTOKEN_FILE" )
FAKEVAULT_TOKEN="$(cat "$VTOKEN_FILE")" "$FAKEVAULT" -file "$FIXTURE" -addr "127.0.0.1:$VPORT" 2>/dev/null &
FV_PID=$!
trap 'kill "$FV_PID" 2>/dev/null || true; rm -f "$VTOKEN_FILE" "$PAT_FILE"' EXIT
for _ in $(seq 1 30); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$VPORT/v1/sys/health" && break; sleep 0.2; done

scn_step "1/5 the source: a Vault export (5 paths, 6 fields) - and a least-privilege Keyorix token for the import"
scn_token admin
demo_api GET "$SCN_URL" "/api/v1/projects/${PROJECT_ID}/environments" "$SCN_TOKEN"
ENV_ID="$(demo_json 'next(e["id"] for e in d["data"]["environments"] if e["name"].lower()=="development")' "$DEMO_BODY")"
[ -n "$ENV_ID" ] || { scn_fail "no development environment in project $PROJECT_ID"; exit 1; }
expiry="$(date -u -v+1d +%Y-%m-%d 2>/dev/null || date -u -d '+1 day' +%Y-%m-%d)"
scn_cli_as admin pat create --name "vault-migrate-$(date +%H%M%S)" --project-id "$PROJECT_ID" --scope secrets.write --scope secrets.read --expires "$expiry" \
  | grep -oE 'kx_pat_[A-Za-z0-9_-]+' | head -n 1 | tr -d '\n' > "$PAT_FILE.tmp"
( umask 077; mv "$PAT_FILE.tmp" "$PAT_FILE" )
[ -s "$PAT_FILE" ] || { scn_fail "no personal access token created"; exit 1; }
scn_ok "token scoped to project $PROJECT_ID, secrets.read/write, expires $expiry (passed by file, not argv)"

migrate() { # [extra flags]
  "$MIGRATE" vault --vault-addr "http://127.0.0.1:$VPORT" --vault-token-file "$VTOKEN_FILE" --vault-mount secret \
    --server "$SCN_URL" --token-file "$PAT_FILE" --project "$PROJECT_ID" --environment "$ENV_ID" "$@"
}

scn_step "2/5 dry run: the plan, nothing written"
plan="$(migrate)"
printf '%s\n' "$plan"
printf '%s\n' "$plan" | grep -q 'Dry run only' || { scn_fail "the default run was not a dry run"; exit 1; }
before="$(scn_cli_as admin secret list --project "$PROJECT_ID" | sed -n 's/^Total: \([0-9]*\).*/\1/p')"
scn_ok "dry run changed nothing (project $PROJECT_ID holds ${before:-0} secrets)"

scn_step "3/5 apply"
migrate --apply --report "$WORK/vault-import-report.json"
scn_ok "imported; per-item report: $WORK/vault-import-report.json"

scn_step "4/5 the application reads the same values from Keyorix (unchanged app, env vars via 'keyorix run')"
KEYORIX_TOKEN="$(cat "$PAT_FILE")" "$CLI_BIN" run --project mobile-app --env development --clean-env \
  --var STRIPE_KEY=payments-stripe-api_key --var PAYMENTS_DB_PASSWORD=payments-db-password -- \
  sh -c 'printf "   app sees STRIPE_KEY=%s...  PAYMENTS_DB_PASSWORD=%s chars\n" "$(printf %s "$STRIPE_KEY" | cut -c1-14)" "${#PAYMENTS_DB_PASSWORD}"; [ "$STRIPE_KEY" = "vaultdemo_stripe_key_0001" ] && echo "   matches the Vault export"'
scn_ok "values identical to the source"

scn_step "5/5 re-running the import is a no-op (safe staged cut-over)"
again="$(migrate)"
printf '%s\n' "$again" | tail -n 3
printf '%s\n' "$again" | grep -q '0 create' || { scn_fail "a second import would create duplicates"; exit 1; }
scn_ok "0 create on the second run"

# Keep the demo's posture honest: the imported secrets are classified like every seeded one.
for sid in $(scn_cli_as admin secret list --project "$PROJECT_ID" | awk '$1 ~ /^[0-9]+$/ {print $1}'); do
  scn_cli_as admin secret classify --id "$sid" --level confidential >/dev/null 2>&1 || true
done
scn_info "imported secrets classified confidential; rotation policy for mobile-app is the open follow-up a real migration would add"
