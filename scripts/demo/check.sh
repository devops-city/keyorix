#!/usr/bin/env bash
# scripts/demo/check.sh -- "will the demo work?" in about 5 minutes.
#
# Walks docs/demo/GOLDEN-PATH.md end to end through the public API only
# (never the database) and prints one line per step:
#   ✅ step (Ns)
#   ❌ step: what broke (where to look)
# then DEMO READY / NOT READY: N problems, exit 0/1.
#
# This checks THIS product's demo golden path specifically, not an
# arbitrary instance: with no --url it brings up its own known-shape demo
# (scripts/demo/up.sh for SQLite; a docker-compose Postgres stack seeded by
# this script for --postgres) and knows the exact org that produces. --url
# only makes sense against an instance that was seeded the same way (the
# CI job's own instance, or a demo you already brought up yourself).
#
# Usage: scripts/demo/check.sh [--url URL] [--sqlite|--postgres] [--keep]
#                              [--ui|--no-ui] [--offline]
#   --url URL     check an already-running, already-seeded instance instead
#                 of bringing one up (and never tears it down).
#   --sqlite      bring up via scripts/demo/up.sh (default).
#   --postgres    bring up via docker compose (docker-compose.yml) against a
#                 throwaway Postgres, seeded by this script.
#   --keep        leave the demo running afterward (for the actual demo).
#                 Ignored with --url (nothing of ours to tear down).
#   --ui          force the Playwright real-backend UI walk (web/e2e/real).
#                 Runs by default if the playwright CLI resolves; pass this
#                 to make a missing/broken install a hard failure instead of
#                 a skip (the default heuristic checks the CLI, not whether
#                 a browser binary is actually downloaded -- a CLI-present/
#                 browser-absent install still fails the real run).
#   --no-ui       never run the UI walk, not even the default auto-detect
#                 (the fast CI path uses this -- no Playwright setup there).
#   --offline     also run the offline-guarantee leg (scripts/airgap-e2e.sh
#                 --network none against the same locally-built image).
#                 Skipped by default -- it's slow and SQLite-image-specific.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# Shared with up.sh: MFA enrolment + MFA-aware API login (#3034).
# shellcheck source=scripts/demo/lib.sh
. "$SCRIPT_DIR/lib.sh"
TOTPGEN_BIN="$REPO_ROOT/bin/totpgen"
ensure_totpgen() {
  [ -x "$TOTPGEN_BIN" ] && return 0
  command -v go >/dev/null 2>&1 || { echo "go is required to build the TOTP helper (scripts/totpgen)"; return 1; }
  GOWORK=off go build -o "$TOTPGEN_BIN" "$REPO_ROOT/scripts/totpgen/main.go"
}

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

URL="" BACKEND="sqlite" KEEP=false UI_MODE="auto" OFFLINE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --sqlite) BACKEND="sqlite"; shift ;;
    --postgres) BACKEND="postgres"; shift ;;
    --keep) KEEP=true; shift ;;
    --ui) UI_MODE="force"; shift ;;
    --no-ui) UI_MODE="skip"; shift ;;
    --offline) OFFLINE=true; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

SCRATCH="$(mktemp -d)"
cleanup_scratch() { rm -rf "$SCRATCH"; }
trap cleanup_scratch EXIT

PROBLEMS=0
FAILED_STEPS=()
TOTAL_START=$SECONDS

# ---------------------------------------------------------------------------
# tiny HTTP/JSON helpers -- public API only, no database access anywhere
# ---------------------------------------------------------------------------
HTTP_CODE=""
RESP_BODY=""
req() { # req METHOD PATH [BEARER_TOKEN] [JSON_BODY]
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o "$SCRATCH/resp.json" -w '%{http_code}' --max-time 10 -X "$method" "${SERVER_URL}${path}")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  HTTP_CODE="$(curl "${args[@]}")"
  RESP_BODY="$(cat "$SCRATCH/resp.json" 2>/dev/null || true)"
}
jget() { # jget '<python expr over d, e.g. d["data"]["token"]>' -- reads $RESP_BODY
  python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    v = $1
    print(v if v is not None else '')
except Exception:
    print('')
" "$RESP_BODY"
}
urlenc() { python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))" "$1"; }
totp_code() { # totp_code BASE32_SECRET
  python3 -c "
import sys, time, hmac, hashlib, base64, struct
secret = sys.argv[1]
secret += '=' * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret.upper())
counter = int(time.time() // 30)
msg = struct.pack('>Q', counter)
h = hmac.new(key, msg, hashlib.sha1).digest()
o = h[19] & 0xf
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print('%06d' % code)
" "$1"
}
get_secret_by_ref() { req GET "/api/v1/secrets/value?ref=$(urlenc "$2")" "$1"; }

# ---------------------------------------------------------------------------
# step runner
# ---------------------------------------------------------------------------
run_step() { # run_step "name" fn_name
  local name="$1" fn="$2"
  local out="$SCRATCH/step.out"
  : > "$out"
  local t0=$SECONDS
  "$fn" >"$out" 2>&1
  local rc=$?
  local dur=$((SECONDS - t0))
  if [ "$rc" -eq 0 ]; then
    local extra=""
    [ -s "$out" ] && extra=" ($(tail -1 "$out"))"
    printf "${GREEN}✅${NC} %s (%ss)%s\n" "$name" "$dur" "$extra"
  else
    PROBLEMS=$((PROBLEMS + 1))
    FAILED_STEPS+=("$name")
    printf "${RED}❌${NC} %s: %s\n" "$name" "$(tail -1 "$out")"
  fi
}

# ---------------------------------------------------------------------------
# bring-up / teardown
# ---------------------------------------------------------------------------
BROUGHT_UP=false
PG_PROJECT="keyorix-demo-check-pg"
PG_ENV_FILE="$SCRATCH/.env.demo-check"

bring_up_sqlite() {
  # up.sh leaves its final admin MFA session here, so step_admin_login can reuse
  # it (the login budget is 10 attempts / 15 min / IP, #2956, and the UI walk
  # needs two of them). Read and deleted in step_admin_login.
  mkdir -p "$REPO_ROOT/.demo-2-check-state"
  UP_SESSION_FILE="$REPO_ROOT/.demo-2-check-state/up-admin-session"
  KEYORIX_DEMO_SESSION_OUT="$UP_SESSION_FILE" "$REPO_ROOT/scripts/demo/up.sh" >"$SCRATCH/up.log" 2>&1
  local rc=$?
  cat "$SCRATCH/up.log"
  return $rc
}

bring_up_postgres() {
  command -v docker >/dev/null 2>&1 || { echo "docker is required"; return 1; }

  # docker-compose.yml's default `backend.image:` is a PINNED released tag
  # (ghcr.io/.../keyorix-server:0.95.3), not this checkout -- using it as-is
  # would silently check an old release instead of the code actually being
  # demoed (confirmed live: 0.95.3 predates #2780/#2781's project-visibility
  # fix and reintroduces the exact bug this script exists to catch). Build
  # the SAME locally-built, web-UI-embedded image up.sh uses for SQLite and
  # override backend to use it via an extra compose file -- the stock
  # docker-compose.yml itself is never modified.
  if ! docker image inspect keyorix-demo:airgap >/dev/null 2>&1; then
    echo "==> building keyorix-demo:airgap (shared with the SQLite path)"
    command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI (see web/package.json)"; return 1; }
    make -C "$REPO_ROOT" populate-webui-dist >/dev/null || { echo "make populate-webui-dist failed"; return 1; }
    docker build -f "$REPO_ROOT/server/Dockerfile" --build-arg BUILD_TAGS=noaws,noazure,nogcp -t keyorix-demo:airgap "$REPO_ROOT" >"$SCRATCH/image-build.log" 2>&1 || {
      cat "$SCRATCH/image-build.log"; echo "docker build failed"; return 1
    }
    git -C "$REPO_ROOT" checkout -- server/webui/dist/index.html 2>/dev/null || true
  fi

  cat > "$PG_ENV_FILE" <<'EOF'
# Throwaway demo-check values -- not security-sensitive, this stack is torn
# down (or re-created) by scripts/demo/check.sh every run.
KEYORIX_DB_PASSWORD=demo-check-db-password-2026
KEYORIX_MASTER_PASSWORD=demo-check-master-passphrase-2026
KEYORIX_BOOTSTRAP_TOKEN=demo-check-bootstrap-token
EOF
  # Same story for the web image: docker-compose.yml pins the RELEASED
  # keyorix-web, which does not match a main backend (login bounced to
  # /login?logout_error=1, POST /auth/logout 400 -- #3035). Build web/ from
  # this checkout instead. The release compose file keeps its pins (checked
  # by deploy/compose_pins_test.go); only this demo/check overlay differs.
  local override_file="$SCRATCH/compose-override.yml"
  cat > "$override_file" <<EOF
services:
  backend:
    image: keyorix-demo:airgap
  web:
    image: keyorix-demo-web:local
    build:
      context: $REPO_ROOT/web
EOF
  docker compose -p "$PG_PROJECT" -f "$REPO_ROOT/docker-compose.yml" -f "$override_file" --env-file "$PG_ENV_FILE" up -d --build >"$SCRATCH/compose-up.log" 2>&1
  local rc=$?
  cat "$SCRATCH/compose-up.log"
  [ "$rc" -eq 0 ] || return 1

  SERVER_URL="http://localhost:8088"
  # /health is nginx's own static liveness check (passes before the backend
  # upstream is actually reachable through it); /api/v1/version genuinely
  # round-trips through nginx to the backend, so wait on that instead.
  local ready=false
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$SERVER_URL/api/v1/version")" = "200" ] && { ready=true; break; }
    sleep 1
  done
  [ "$ready" = true ] || { echo "postgres stack never became reachable through nginx -- docker compose -p $PG_PROJECT logs"; return 1; }

  local init_ok=false
  for _ in $(seq 1 10); do
    req POST /system/init "" '{"username":"admin","email":"admin@keyorix.demo","password":"Correct-Horse-Battery-2026","bootstrap_token":"demo-check-bootstrap-token"}'
    [ "$HTTP_CODE" = "200" ] && { init_ok=true; break; }
    sleep 1
  done
  [ "$init_ok" = true ] || { echo "POST /system/init returned $HTTP_CODE: $RESP_BODY"; return 1; }

  seed_demo_org
}

# seed_demo_org replicates scripts/demo/up.sh's seed (same project/env id
# layout: default=1 [development=1,staging=2,production=3],
# backend-api=2 [4,5,6], mobile-app=3 [7,8,9]) via the public API only, for
# the Postgres path (up.sh itself is SQLite-only, single-container).
seed_demo_org() {
  # security.require_mfa is ON by default: a fresh admin is refused (403
  # MFAEnrollmentRequired) until it enrols TOTP, exactly as up.sh handles it
  # (#3034) -- same helper, scripts/demo/lib.sh.
  ensure_totpgen || return 1
  demo_enroll_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" || { echo "admin MFA enrolment failed while seeding"; return 1; }
  ADMIN_MFA_SECRET="$DEMO_MFA_SECRET"
  ADMIN_TOKEN="$DEMO_TOKEN"
  ADMIN_SESSION_FROM_SEED=true

  req POST /api/v1/projects "$ADMIN_TOKEN" '{"name":"backend-api","description":"Backend API"}'
  req POST /api/v1/projects "$ADMIN_TOKEN" '{"name":"mobile-app","description":"Mobile App"}'
  req POST /api/v1/groups "$ADMIN_TOKEN" '{"name":"platform-team","description":"Platform team"}'
  req POST /api/v1/groups "$ADMIN_TOKEN" '{"name":"mobile-team","description":"Mobile team"}'

  req POST /api/v1/users "$ADMIN_TOKEN" '{"username":"alice","email":"alice@keyorix.demo","password":"Nebula-Quartz-Flagstone-2026","display_name":"Alice"}'
  local alice_id; alice_id="$(jget 'd["data"]["id"]')"
  [ -n "$alice_id" ] || { echo "user create (alice) returned no id: $RESP_BODY"; return 1; }
  req GET /api/v1/projects "$ADMIN_TOKEN"
  local backend_id
  backend_id="$(jget 'next(p["id"] for p in d["data"]["projects"] if p["name"]=="backend-api")')"
  req GET /api/v1/roles "$ADMIN_TOKEN"
  local viewer_role_id
  viewer_role_id="$(jget 'next(r["id"] for r in d["data"]["roles"] if r["name"]=="project_viewer")')"
  [ -n "$viewer_role_id" ] || { echo "no project_viewer role found: $RESP_BODY"; return 1; }
  req POST /api/v1/user-roles "$ADMIN_TOKEN" "{\"user_id\":$alice_id,\"role_id\":$viewer_role_id,\"project_id\":$backend_id}"

  req GET /api/v1/projects/1/environments "$ADMIN_TOKEN"
  local default_dev
  default_dev="$(jget 'next(e["id"] for e in d["data"]["environments"] if e["name"]=="development")')"
  req GET "/api/v1/projects/$backend_id/environments" "$ADMIN_TOKEN"
  local backend_dev backend_prod
  backend_dev="$(jget 'next(e["id"] for e in d["data"]["environments"] if e["name"]=="development")')"
  backend_prod="$(jget 'next(e["id"] for e in d["data"]["environments"] if e["name"]=="production")')"

  req POST /api/v1/secrets "$ADMIN_TOKEN" "{\"name\":\"stripe-api-key\",\"value\":\"sk_test_demo_seed_v1\",\"type\":\"api_key\",\"project_id\":1,\"environment_id\":$default_dev}"
  local stripe_id; stripe_id="$(jget 'd["data"]["id"]')"
  req POST "/api/v1/secrets/$stripe_id/rotate" "$ADMIN_TOKEN" '{"new_value":"sk_test_demo_seed_v2"}'
  req POST /api/v1/secrets "$ADMIN_TOKEN" "{\"name\":\"db-password\",\"value\":\"demo-db-pass-v1\",\"type\":\"password\",\"project_id\":$backend_id,\"environment_id\":$backend_dev}"
  # The Secrets tab opens on Production: keep a secret there too, as up.sh does.
  req POST /api/v1/secrets "$ADMIN_TOKEN" "{\"name\":\"payments-webhook-secret\",\"value\":\"whsec_demo_seed_v1\",\"type\":\"password\",\"project_id\":$backend_id,\"environment_id\":$backend_prod}"

  req POST /api/v1/projects/1/machine-identities "$ADMIN_TOKEN" '{"name":"ci-app","identity_type":"ci"}'
  local machine_id; machine_id="$(jget 'd["data"]["machine_identity"]["id"]')"
  req POST "/api/v1/projects/1/machine-identities/$machine_id/roles" "$ADMIN_TOKEN" "{\"role_id\":$viewer_role_id}"
  req POST "/api/v1/projects/1/machine-identities/$machine_id/tokens" "$ADMIN_TOKEN" '{"name":"ci-pipeline-token"}'
  MACHINE_TOKEN="$(jget 'd["data"]["token"]')"
  [ -n "$MACHINE_TOKEN" ] || { echo "machine token issue returned no token: $RESP_BODY"; return 1; }

  req GET "/api/v1/secrets/$stripe_id?include_value=true" "$ADMIN_TOKEN"
  # populate at least one audit event via a machine read, matching up.sh
  get_secret_by_ref "$MACHINE_TOKEN" "default/development/stripe-api-key"

  echo "$MACHINE_TOKEN" > "$REPO_ROOT/.demo-2-pg-state"
  return 0
}

teardown_sqlite() { "$REPO_ROOT/scripts/demo/down.sh" --wipe >/dev/null 2>&1 || true; }
teardown_postgres() {
  docker compose -p "$PG_PROJECT" -f "$REPO_ROOT/docker-compose.yml" -f "$SCRATCH/compose-override.yml" --env-file "$PG_ENV_FILE" down -v >/dev/null 2>&1 || true
  rm -f "$REPO_ROOT/.demo-2-pg-state"
}

# ---------------------------------------------------------------------------
# resolve target + credentials
# ---------------------------------------------------------------------------
ADMIN_USER="admin"
ADMIN_PASSWORD="Correct-Horse-Battery-2026"
ADMIN_SESSION_FROM_SEED=false
ADMIN_MFA_SECRET="${ADMIN_MFA_SECRET:-}"   # set by the Postgres seed, or read from .demo-2-state below
ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"
MACHINE_TOKEN=""

if [ -n "$URL" ]; then
  SERVER_URL="$URL"
else
  echo "==> bringing up the $BACKEND demo"
  if [ "$BACKEND" = "sqlite" ]; then
    SERVER_URL="http://localhost:${KEYORIX_DEMO_PORT:-8080}"
    bring_up_sqlite || { echo "demo bring-up failed -- see scripts/demo/up.sh output above"; exit 1; }
  else
    bring_up_postgres || { echo "demo bring-up failed -- see docker compose output above"; exit 1; }
  fi
  BROUGHT_UP=true
fi

if [ "$BACKEND" = "sqlite" ] && [ -f "$REPO_ROOT/.demo-2-state" ]; then
  MACHINE_TOKEN="$(grep -oE 'kx_machine_[A-Za-z0-9_-]+' "$REPO_ROOT/.demo-2-state" | head -1)"
  # up.sh enrols TOTP for the admin and records the key there; the admin login
  # step needs it to answer the second-factor challenge.
  [ -n "$ADMIN_MFA_SECRET" ] || ADMIN_MFA_SECRET="$(sed -n 's/^  Admin TOTP key: \([A-Z2-7]*\).*/\1/p' "$REPO_ROOT/.demo-2-state" | head -1)"
elif [ "$BACKEND" = "postgres" ] && [ -f "$REPO_ROOT/.demo-2-pg-state" ]; then
  MACHINE_TOKEN="$(cat "$REPO_ROOT/.demo-2-pg-state")"
fi

CHECK_STATE_DIR="$REPO_ROOT/.demo-2-check-state"
mkdir -p "$CHECK_STATE_DIR"

ADMIN_TOKEN="${ADMIN_TOKEN:-}"   # the Postgres seed leaves its MFA session here
ALICE_TOKEN=""
VERIFY_PROJECT_ID=""
VERIFY_ENV_ID=""
VERIFY_SECRET_ID=""

# ---------------------------------------------------------------------------
# steps
# ---------------------------------------------------------------------------
step_health() {
  req GET /health ""
  [ "$HTTP_CODE" = "200" ] || { echo "GET /health returned $HTTP_CODE -- server/http/router.go health handler"; return 1; }
  # Direct (SQLite, single binary): JSON {"status":"healthy",...}. Through the
  # Postgres compose stack's nginx front door: nginx answers /health itself
  # with a plain-text "healthy" (its own liveness check, not proxied) --
  # either counts.
  local status; status="$(jget 'd["status"]')"
  if [ "$status" != "healthy" ] && ! grep -qi '^healthy' "$SCRATCH/resp.json"; then
    echo "GET /health returned neither {\"status\":\"healthy\"} nor plain 'healthy': $RESP_BODY"
    return 1
  fi
  return 0
}

step_version() {
  req GET /api/v1/version ""
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/version returned $HTTP_CODE"; return 1; }
  local v; v="$(jget 'd["api_version"]')"
  [ -n "$v" ] || { echo "GET /api/v1/version returned no api_version: $RESP_BODY"; return 1; }
  echo "api_version=$v"
  return 0
}

step_webui() {
  local code body_file="$SCRATCH/root.html"
  code="$(curl -s -o "$body_file" -w '%{http_code}' --max-time 10 "$SERVER_URL/")"
  [ "$code" = "200" ] || { echo "GET / returned $code, expected the embedded web UI -- see #2752, scripts/demo/up.sh's populate-webui-dist step"; return 1; }
  grep -qi '<div id="root"' "$body_file" || grep -qi '<!doctype html' "$body_file" || {
    echo "GET / did not look like the web UI's index.html -- #2752 (web UI not embedded in this image)"; return 1
  }
  return 0
}

step_admin_login() {
  # The Postgres seed already logged the admin in with a real MFA challenge; its
  # session is reused rather than spending two more of the 10-per-15-minute login
  # attempts (#2956) on an identical login.
  if [ "$ADMIN_SESSION_FROM_SEED" = true ] && [ -n "$ADMIN_TOKEN" ]; then
    req GET /api/v1/projects "$ADMIN_TOKEN"
    [ "$HTTP_CODE" = "200" ] || { echo "the admin session from the seed's MFA login is not accepted ($HTTP_CODE): $RESP_BODY"; return 1; }
    echo "reused the seed's MFA login"
    return 0
  fi
  if [ -n "${UP_SESSION_FILE:-}" ] && [ -s "$UP_SESSION_FILE" ]; then
    ADMIN_TOKEN="$(cat "$UP_SESSION_FILE")"
    rm -f "$UP_SESSION_FILE"
    req GET /api/v1/projects "$ADMIN_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
      echo "reused up.sh's MFA login"
      return 0
    fi
    ADMIN_TOKEN=""
  fi
  # The demo admin has MFA (require_mfa is on): answer the challenge with the
  # TOTP key up.sh / the Postgres seed recorded. Against a --url target with no
  # known key a plain password login is attempted and fails clearly if MFA is on.
  [ -z "$ADMIN_MFA_SECRET" ] || ensure_totpgen || return 1
  demo_login_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" "$ADMIN_MFA_SECRET" || { echo "admin login failed -- server/http/handlers/auth.go Login / mfa.go VerifyMFA"; return 1; }
  ADMIN_TOKEN="$DEMO_TOKEN"
  return 0
}

step_alice_login() {
  # alice has no TOTP yet (the demo has her enrol live): a password login must
  # still succeed, but only into the MFA-enrolment-only session.
  req POST /auth/login "" "{\"username\":\"alice\",\"password\":\"$ALICE_PASSWORD\"}"
  [ "$HTTP_CODE" = "200" ] || { echo "POST /auth/login (alice) returned $HTTP_CODE: $RESP_BODY"; return 1; }
  # Already enrolled (the presenter did the live enrolment on a --keep instance):
  # the password step now asks for a code, which is the expected end state.
  [ "$(jget 'd["data"].get("mfa_required")')" = "True" ] && { echo "alice has enrolled TOTP; password step asks for a code"; return 0; }
  local t; t="$(jget 'd["data"]["token"]')"
  [ -n "$t" ] || { echo "alice login succeeded but no token in response: $RESP_BODY"; return 1; }
  req GET /api/v1/projects "$t"
  [ "$HTTP_CODE" = "403" ] || { echo "alice (no MFA yet) got $HTTP_CODE listing projects, expected 403 MFAEnrollmentRequired -- security.require_mfa not enforced?"; return 1; }
  return 0
}

step_alice_projects_nonempty() {
  req GET /api/v1/projects "$ALICE_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/projects (alice) returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local n; n="$(jget 'len(d["data"]["projects"])')"
  [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null || { echo "a non-admin sees an EMPTY project list (len=$n) -- PROJ-ACCESS-1 class; server/http/handlers/catalog.go ListProjects / internal/core/project_visibility.go"; return 1; }
  echo "$n project(s) visible"
  return 0
}

step_alice_dashboard_secret_count() {
  req GET /api/v1/dashboard/stats "$ALICE_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/dashboard/stats (alice) returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local dash_total; dash_total="$(jget 'd["data"]["totalSecrets"]')"
  req GET /api/v1/secrets "$ALICE_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/secrets (alice) returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local readable_total; readable_total="$(jget 'd["data"]["total"]')"
  if [ "${readable_total:-0}" -gt 0 ] 2>/dev/null && [ "${dash_total:-0}" != "$readable_total" ]; then
    echo "dashboard totalSecrets=$dash_total but alice can actually read $readable_total -- PROJ-ACCESS-1 dashboard count bug, internal/core/dashboard.go GetDashboardStats (PR #2859 fixes this, not yet merged)"
    return 1
  fi
  echo "totalSecrets=$dash_total, matches $readable_total readable"
  return 0
}

step_verify_create() {
  local name="demo-check-verify-$$"
  req POST /api/v1/projects "$ADMIN_TOKEN" "{\"name\":\"$name\",\"description\":\"scripts/demo/check.sh scratch project\"}"
  [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || { echo "POST /api/v1/projects returned $HTTP_CODE: $RESP_BODY"; return 1; }
  VERIFY_PROJECT_ID="$(jget 'd["data"]["id"]')"
  [ -n "$VERIFY_PROJECT_ID" ] || { echo "project create returned no id: $RESP_BODY"; return 1; }

  req GET "/api/v1/projects/$VERIFY_PROJECT_ID/environments" "$ADMIN_TOKEN"
  VERIFY_ENV_ID="$(jget 'next(e["id"] for e in d["data"]["environments"] if e["name"]=="development")')"
  [ -n "$VERIFY_ENV_ID" ] || { echo "no development environment found on fresh project: $RESP_BODY"; return 1; }

  req POST /api/v1/secrets "$ADMIN_TOKEN" "{\"name\":\"check-secret\",\"value\":\"v1-value\",\"type\":\"text\",\"project_id\":$VERIFY_PROJECT_ID,\"environment_id\":$VERIFY_ENV_ID}"
  [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || { echo "POST /api/v1/secrets returned $HTTP_CODE: $RESP_BODY"; return 1; }
  VERIFY_SECRET_ID="$(jget 'd["data"]["id"]')"
  [ -n "$VERIFY_SECRET_ID" ] || { echo "secret create returned no id: $RESP_BODY"; return 1; }
  return 0
}

step_verify_read_back() {
  [ -n "$VERIFY_SECRET_ID" ] || { echo "no secret from the create step to read back"; return 1; }
  req GET "/api/v1/secrets/$VERIFY_SECRET_ID?include_value=true" "$ADMIN_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/secrets/$VERIFY_SECRET_ID returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local v; v="$(jget 'd["data"]["value"]')"
  [ "$v" = "v1-value" ] || { echo "read-back value '$v' != what was written -- server/http/handlers/secrets_crud.go GetSecret"; return 1; }
  return 0
}

step_verify_rotate() {
  [ -n "$VERIFY_SECRET_ID" ] || { echo "no secret from the create step to rotate"; return 1; }
  req POST "/api/v1/secrets/$VERIFY_SECRET_ID/rotate" "$ADMIN_TOKEN" '{"new_value":"v2-value"}'
  [ "$HTTP_CODE" = "200" ] || { echo "POST /api/v1/secrets/$VERIFY_SECRET_ID/rotate returned $HTTP_CODE: $RESP_BODY"; return 1; }
  req GET "/api/v1/secrets/$VERIFY_SECRET_ID?include_value=true" "$ADMIN_TOKEN"
  local v; v="$(jget 'd["data"]["value"]')"
  [ "$v" = "v2-value" ] || { echo "post-rotate value '$v' != v2-value -- server/http/handlers/secrets_crud.go RotateSecret"; return 1; }
  return 0
}

step_verify_history() {
  [ -n "$VERIFY_SECRET_ID" ] || { echo "no secret from the create step to check history on"; return 1; }
  req GET "/api/v1/secrets/$VERIFY_SECRET_ID/versions" "$ADMIN_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/secrets/$VERIFY_SECRET_ID/versions returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local n; n="$(jget 'len(d["data"]["versions"])')"
  [ -n "$n" ] && [ "$n" -ge 2 ] 2>/dev/null || { echo "expected >=2 versions after a rotate, got $n -- server/http/handlers/secrets_crud.go GetSecretVersions"; return 1; }
  # cleanup -- scratch project, not part of the demo narrative
  req DELETE "/api/v1/projects/$VERIFY_PROJECT_ID" "$ADMIN_TOKEN"
  echo "$n versions"
  return 0
}

step_acl_can_read() {
  get_secret_by_ref "$ALICE_TOKEN" "backend-api/development/db-password"
  [ "$HTTP_CODE" = "200" ] || { echo "alice (project_viewer on backend-api) could not read backend-api/development/db-password: $HTTP_CODE $RESP_BODY -- server/middleware/auth.go RequireScopedSecretRefPermission"; return 1; }
  return 0
}

step_acl_cannot_read() {
  get_secret_by_ref "$ALICE_TOKEN" "default/development/stripe-api-key"
  [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "404" ] || { echo "alice (no role on 'default') got $HTTP_CODE reading default/development/stripe-api-key, expected 403/404 -- an ACL regression"; return 1; }
  return 0
}

step_machine_read_by_ref() {
  [ -n "$MACHINE_TOKEN" ] || { echo "no machine token found (.demo-2-state / .demo-2-pg-state missing) -- was this instance brought up via scripts/demo/up.sh or this script?"; return 1; }
  get_secret_by_ref "$MACHINE_TOKEN" "default/development/stripe-api-key"
  [ "$HTTP_CODE" = "200" ] || { echo "ci-app machine token could not read default/development/stripe-api-key by ref: $HTTP_CODE $RESP_BODY -- server/http/handlers/secrets_crud.go GetSecretValueByRef"; return 1; }
  local v; v="$(jget 'd["data"]["value"]')"
  [ -n "$v" ] || { echo "machine read by ref returned no value: $RESP_BODY"; return 1; }
  return 0
}

step_mfa() {
  local username="mfa-demo" email="mfa-demo@keyorix.demo" password="Obsidian-Lumen-Thicket-77"
  local state_file="$CHECK_STATE_DIR/mfa-secret"

  req POST /api/v1/users "$ADMIN_TOKEN" "{\"username\":\"$username\",\"email\":\"$email\",\"password\":\"$password\",\"display_name\":\"MFA Demo\"}"
  # 409 (already exists, from a previous run) is fine; any other setup problem
  # surfaces below when login itself fails.
  #
  # This user doubles as the MFA-enrolled "viewer" the alice checks run as: under
  # require_mfa the real alice stays confined until she enrols, and the demo has
  # her do that live (GOLDEN-PATH section 2) -- so the checks must not enrol HER.
  # Same grant as alice's (project_viewer on backend-api); reusing this user also
  # keeps the whole run inside the login budget (10 attempts / 15 min / IP, each
  # login and each MFA verify counts; #2956).
  local viewer_id; viewer_id="$(jget 'd["data"]["id"]')"
  if [ -n "$viewer_id" ]; then
    req GET /api/v1/projects "$ADMIN_TOKEN"
    local backend_id; backend_id="$(jget 'next(p["id"] for p in d["data"]["projects"] if p["name"]=="backend-api")')"
    req GET /api/v1/roles "$ADMIN_TOKEN"
    local viewer_role_id; viewer_role_id="$(jget 'next(r["id"] for r in d["data"]["roles"] if r["name"]=="project_viewer")')"
    req POST /api/v1/user-roles "$ADMIN_TOKEN" "{\"user_id\":$viewer_id,\"role_id\":$viewer_role_id,\"project_id\":$backend_id}"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || { echo "project_viewer grant for $username returned $HTTP_CODE: $RESP_BODY"; return 1; }
  fi

  req POST /auth/login "" "{\"username\":\"$username\",\"password\":\"$password\"}"
  [ "$HTTP_CODE" = "200" ] || { echo "mfa-demo login (password step) returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local mfa_required; mfa_required="$(jget 'd["data"].get("mfa_required")')"
  local login_token; login_token="$(jget 'd["data"].get("token","")')"
  local challenge secret code

  if [ "$mfa_required" = "True" ]; then
    [ -f "$state_file" ] || { echo "mfa-demo already has MFA enrolled but $state_file is missing locally -- cannot compute a code; scripts/demo/down.sh --wipe and retry"; return 1; }
    secret="$(cat "$state_file")"
    challenge="$(jget 'd["data"]["mfa_challenge"]')"
    code="$(totp_code "$secret")"
    req POST /auth/mfa/verify "" "{\"mfa_challenge\":\"$challenge\",\"code\":\"$code\"}"
    [ "$HTTP_CODE" = "200" ] || { echo "MFA login verify failed: $HTTP_CODE $RESP_BODY -- server/http/handlers/mfa.go VerifyMFA, #2737/#2738"; return 1; }
    ALICE_TOKEN="$(jget 'd["data"]["token"]')"
    return 0
  fi

  req POST /api/v1/auth/mfa/enroll "$login_token" "{}"
  [ "$HTTP_CODE" = "200" ] || { echo "MFA enroll failed: $HTTP_CODE $RESP_BODY -- server/http/handlers/mfa.go EnrollMFA"; return 1; }
  secret="$(jget 'd["data"]["secret"]')"
  [ -n "$secret" ] || { echo "MFA enroll returned no secret: $RESP_BODY"; return 1; }
  code="$(totp_code "$secret")"
  req POST /api/v1/auth/mfa/activate "$login_token" "{\"code\":\"$code\",\"password\":\"$password\"}"
  [ "$HTTP_CODE" = "200" ] || { echo "MFA activate failed: $HTTP_CODE $RESP_BODY -- server/http/handlers/mfa.go ActivateMFA"; return 1; }
  echo "$secret" > "$state_file"

  # internal/core/mfa.go's validateTOTPStep enforces single-use (anti-replay):
  # a code already accepted once (by the activate call just above) is rejected
  # on a second use even if the math still matches, so wait for a fresh
  # 30s step before computing the verify code below -- otherwise this would
  # intermittently fail on its own replay, not a product bug.
  python3 -c "import time; t=time.time()%30; time.sleep(31-t)"

  req POST /auth/login "" "{\"username\":\"$username\",\"password\":\"$password\"}"
  [ "$HTTP_CODE" = "200" ] || { echo "post-enroll login returned $HTTP_CODE: $RESP_BODY"; return 1; }
  mfa_required="$(jget 'd["data"].get("mfa_required")')"
  [ "$mfa_required" = "True" ] || { echo "post-enroll login did not challenge for MFA (mfa_required=$mfa_required) -- enrollment did not take effect"; return 1; }
  challenge="$(jget 'd["data"]["mfa_challenge"]')"
  code="$(totp_code "$secret")"
  req POST /auth/mfa/verify "" "{\"mfa_challenge\":\"$challenge\",\"code\":\"$code\"}"
  [ "$HTTP_CODE" = "200" ] || { echo "MFA login verify failed right after enrolling: $HTTP_CODE $RESP_BODY"; return 1; }
  ALICE_TOKEN="$(jget 'd["data"]["token"]')"
  return 0
}

step_audit_logs() {
  req GET "/api/v1/audit/logs?action=secret.read&page_size=1" "$ADMIN_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/audit/logs returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local n; n="$(jget 'd["data"]["total"]')"
  [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null || { echo "expected at least one secret.read audit event, got $n -- internal/core/audit.go"; return 1; }
  echo "$n secret.read event(s)"
  return 0
}

step_audit_verify() {
  req GET /api/v1/audit/verify "$ADMIN_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/audit/verify returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local valid; valid="$(jget 'd["data"]["valid"]')"
  [ "$valid" = "True" ] || {
    local first_broken; first_broken="$(jget 'd["data"].get("first_broken_id")')"
    echo "audit chain verify: BROKEN (first broken id: $first_broken) -- internal/core audit chain, admin verify-audit"
    return 1
  }
  return 0
}

step_posture() {
  req GET /api/v1/compliance/posture "$ADMIN_TOKEN"
  [ "$HTTP_CODE" = "200" ] || { echo "GET /api/v1/compliance/posture returned $HTTP_CODE: $RESP_BODY"; return 1; }
  local degraded; degraded="$(jget 'd["data"].get("degraded")')"
  if [ "$degraded" = "True" ]; then
    local reasons; reasons="$(jget '",".join(d["data"].get("degraded_reasons") or [])')"
    echo "compliance posture is DEGRADED: $reasons -- internal/core/dashboard.go GetCompliancePosture"
    return 1
  fi
  return 0
}

LAST_P50_MS=""
step_latency() {
  local n=50 times_file="$SCRATCH/latencies.txt"
  : > "$times_file"
  local ref; ref="$(urlenc "default/development/stripe-api-key")"
  for _ in $(seq 1 "$n"); do
    curl -s -o /dev/null -w '%{time_total}\n' --max-time 5 \
      -H "Authorization: Bearer $ADMIN_TOKEN" "${SERVER_URL}/api/v1/secrets/value?ref=$ref" >>"$times_file"
  done
  local p50; p50="$(sort -n "$times_file" | awk -v n="$n" 'NR==int(n/2)+1{print; exit}')"
  [ -n "$p50" ] || { echo "could not measure any secret-read latency samples"; return 1; }
  LAST_P50_MS="$(python3 -c "print(round(float('$p50')*1000,1))")"
  local baseline_file="$REPO_ROOT/scripts/demo/latency-baseline.txt"
  if [ -f "$baseline_file" ]; then
    local baseline; baseline="$(head -1 "$baseline_file" | tr -d '[:space:]')"
    local is_10x; is_10x="$(python3 -c "b=float('$baseline') if '$baseline' else 0; print('1' if b>0 and float('$LAST_P50_MS')>=10*b else '0')")"
    if [ "$is_10x" = "1" ]; then
      echo "p50 ${LAST_P50_MS}ms is >=10x the recorded baseline ${baseline}ms -- scripts/demo/latency-baseline.txt"
      return 1
    fi
    echo "p50=${LAST_P50_MS}ms over $n reads (baseline ${baseline}ms, informational)"
  else
    echo "p50=${LAST_P50_MS}ms over $n reads (no baseline on file yet, informational)"
  fi
  return 0
}

step_offline() {
  KEYORIX_AIRGAP_E2E_IMAGE=keyorix-demo:airgap "$REPO_ROOT/scripts/airgap-e2e.sh"
}

step_ui() {
  if [ "$UI_MODE" = "auto" ]; then
    (cd "$REPO_ROOT/web" && pnpm exec playwright --version >/dev/null 2>&1) || {
      echo "SKIP: Playwright not installed (cd web && pnpm install && pnpm exec playwright install chromium) -- pass --ui to make this a hard failure"
      return 0
    }
  fi
  (cd "$REPO_ROOT/web" && pnpm exec playwright --version >/dev/null 2>&1) || {
    echo "Playwright is not installed -- cd web && pnpm install && pnpm exec playwright install chromium"
    return 1
  }
  # The demo admin is MFA-enrolled: hand the spec the TOTP key (env only, never
  # printed) and the last step already spent, so it computes a strictly later code.
  local totp_last=0
  [ -z "$ADMIN_MFA_SECRET" ] || totp_last="$(demo_totp_last_step "$ADMIN_MFA_SECRET")"
  (
    cd "$REPO_ROOT/web" || exit 1
    export KEYORIX_E2E_BACKEND_URL="$SERVER_URL"
    export KEYORIX_E2E_ADMIN_USERNAME="$ADMIN_USER"
    export KEYORIX_E2E_ADMIN_PASSWORD="$ADMIN_PASSWORD"
    if [ -n "$ADMIN_MFA_SECRET" ]; then
      export KEYORIX_E2E_ADMIN_TOTP_SECRET="$ADMIN_MFA_SECRET"
      export KEYORIX_E2E_ADMIN_TOTP_LAST_STEP="$totp_last"
    fi
    export KEYORIX_E2E_WEB_PORT=18199
    pnpm exec playwright test --config=playwright.config.real.ts e2e/real/pages.spec.ts
  )
}

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
echo ""
echo "Demo readiness check -- $SERVER_URL ($BACKEND)"
echo ""

run_step "health/version"            step_health
run_step "api version"               step_version
run_step "web UI served (#2752)"     step_webui
run_step "admin login"               step_admin_login
run_step "alice (non-admin) login"   step_alice_login
run_step "mfa: enroll + login (viewer session for the alice checks)" step_mfa
run_step "alice: project list non-empty"      step_alice_projects_nonempty
run_step "alice: dashboard secret count"      step_alice_dashboard_secret_count
run_step "verify-write: create project/env/secret" step_verify_create
run_step "verify-write: read back"            step_verify_read_back
run_step "verify-write: rotate"               step_verify_rotate
run_step "verify-write: version history"      step_verify_history
run_step "acl: alice can read backend-api secret"   step_acl_can_read
run_step "acl: alice cannot read default secret"    step_acl_cannot_read
run_step "machine identity: read secret by ref"     step_machine_read_by_ref
run_step "audit: log shows actions"   step_audit_logs
run_step "audit: chain verify"        step_audit_verify
run_step "posture report"             step_posture
run_step "latency: p50 secret read"   step_latency

if [ "$OFFLINE" = true ]; then
  run_step "offline guarantee (airgap-e2e)" step_offline
fi
if [ "$UI_MODE" != "skip" ]; then
  run_step "UI walk (Playwright, e2e/real)" step_ui
fi

if [ "$BROUGHT_UP" = true ] && [ "$KEEP" != true ]; then
  echo ""
  echo "==> tearing down the $BACKEND demo (pass --keep to leave it running)"
  if [ "$BACKEND" = "sqlite" ]; then teardown_sqlite; else teardown_postgres; fi
fi

echo ""
TOTAL_DUR=$((SECONDS - TOTAL_START))
if [ "$PROBLEMS" -eq 0 ]; then
  printf "${GREEN}DEMO READY${NC} (%ss)\n" "$TOTAL_DUR"
  exit 0
else
  printf "${RED}NOT READY: %s problem(s)${NC} (%ss)\n" "$PROBLEMS" "$TOTAL_DUR"
  for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
  exit 1
fi
