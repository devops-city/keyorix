#!/usr/bin/env bash
# scripts/demo/up.sh — one-command air-gapped Keyorix demo.
#
# Builds (once) a local air-gapped server image WITH the web UI embedded, from
# THIS checkout, so the demo always matches the code you are about to show (the
# published airgap image embeds the UI since v0.96.0, #2752, but may differ from the
# checkout). It runs populate-webui-dist before the docker build itself, exactly as
# `make release`'s binary-tarball path does. Then starts a single
# SQLite-backed container (no Postgres dependency — matches the air-gapped
# edition's single-binary pitch), seeds a realistic org through the public
# API/CLI only (never the database directly), and prints the URL + demo
# logins.
#
# MFA: Keyorix ships with security.require_mfa ON (ADR-112) and the demo keeps
# it on. After bootstrapping the admin this script therefore enrols TOTP for it
# through the real API (scripts/demo/lib.sh, shared with check.sh; no database
# writes), prints the TOTP secret / otpauth URI (and a QR code when `qrencode`
# is installed) for the presenter's authenticator app, and logs in with a valid
# code before seeding. Credentials reach the CLI via environment variables or
# stdin only, never as command-line flags, so the presenter's output carries no
# "passing --password on the command line is insecure" warnings.
#
# All-or-nothing seed: if anything fails between starting a fresh container
# and writing .demo-2-state, the container and data volume are removed again
# so the next run starts clean instead of finding a half-seeded system.
#
# Demo-only files this script leaves in the checkout (all gitignored):
#   .demo-2-state                      what it prints (logins, TOTP key, token)
#   .demo-2-cli-home/demo-secrets.env  0600, DEMO ONLY: the demo's fixed master
#                                      passphrase as KEYORIX_DEMO_MASTER_PASSWORD,
#                                      for docs/demo/GOLDEN-PATH.md's backup step
# and one extra local image, keyorix-demo-sqlite:local (alpine + sqlite3), built
# once so the tamper demo needs no network on stage.
#
# Idempotent: safe to re-run. If the demo is already up and seeded, it just
# reprints the URL + logins (read from .demo-2-state, written on first run —
# a machine token is shown exactly once by the product itself, so a second
# run cannot regenerate it without destroying and re-seeding).
#
# Offline once the image exists: building the image needs network (base
# image pull, Go module download, pnpm install) exactly once; every run
# after that — including the container boot and the full seed walk below —
# makes zero outbound network calls (proven by scripts/airgap-e2e.sh and by
# this script's own CI coverage, journey17).
#
# Stale images (#3149): the image is labelled with a fingerprint of the source tree
# it was built from (scripts/demo/image-stamp.sh). A run reuses the image only when
# that label matches the checkout; otherwise it says so and rebuilds. --no-build
# never builds and fails fast, with the fix, when the image is missing or stale.
# Rebuilding re-tags the image, so it is refused while another container is running
# from that tag (set KEYORIX_DEMO_IMAGE to a name of your own on a shared host).
#
# Usage: scripts/demo/up.sh [--rebuild | --no-build]
#   --rebuild    force a fresh image build even if the image matches the checkout
#   --no-build   never build; fail with instructions if the image is missing or stale

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

IMAGE_TAG="${KEYORIX_DEMO_IMAGE:-keyorix-demo:airgap}"
CONTAINER_NAME="${KEYORIX_DEMO_CONTAINER:-keyorix-demo}"
VOLUME_NAME="${KEYORIX_DEMO_VOLUME:-keyorix-demo-data}"
PORT="${KEYORIX_DEMO_PORT:-8080}"
STATE_FILE="$REPO_ROOT/.demo-2-state"
CLI_HOME="$REPO_ROOT/.demo-2-cli-home"
SECRETS_ENV_FILE="$CLI_HOME/demo-secrets.env"
SQLITE_TOOL_IMAGE="${KEYORIX_DEMO_SQLITE_IMAGE:-keyorix-demo-sqlite:local}"

# Fixed, clearly-labeled demo credentials — not security-sensitive, this is a
# throwaway local demo environment, not a real deployment. Fixed values make
# re-runs idempotent without needing to persist secrets outside the state file.
ADMIN_USER="admin"
ADMIN_EMAIL="admin@keyorix.demo"
ADMIN_PASSWORD="Correct-Horse-Battery-2026"
BOOTSTRAP_TOKEN="keyorix-demo-bootstrap-token"
ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"
SECOFFICER_PASSWORD="Granite-Meadow-Lantern-2026"
MASTER_PASSWORD="keyorix-demo-master-passphrase-2026"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
step() { echo -e "${CYAN}==>${NC} $1"; }
info() { echo -e "${BLUE}  i${NC} $1"; }
ok()   { echo -e "${GREEN}  ok${NC} $1"; }
warn() { echo -e "${YELLOW}  !${NC} $1"; }

# shellcheck source=scripts/demo/lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/demo/image-stamp.sh
. "$SCRIPT_DIR/image-stamp.sh"

REBUILD=false
NO_BUILD=false
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=true ;;
    --no-build) NO_BUILD=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done
if [ "$REBUILD" = true ] && [ "$NO_BUILD" = true ]; then
  echo "--rebuild and --no-build contradict each other; pass one" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required (JSON handling in scripts/demo/lib.sh)" >&2; exit 1; }

CLI_BIN="$REPO_ROOT/bin/keyorix"
if [ ! -x "$CLI_BIN" ]; then
  step "Building the CLI (used by this script to seed the demo, not a build dependency of the image)"
  make -C "$REPO_ROOT" build-cli >/dev/null
fi

TOTPGEN_BIN="$REPO_ROOT/bin/totpgen"
if [ ! -x "$TOTPGEN_BIN" ]; then
  # Stands in for the presenter's authenticator app (scripts/totpgen is a
  # test/CI helper, never part of the shipped binaries).
  command -v go >/dev/null 2>&1 || { echo "go is required to build the TOTP helper (scripts/totpgen)" >&2; exit 1; }
  step "Building the TOTP helper (stands in for an authenticator app while seeding)"
  GOWORK=off go build -o "$TOTPGEN_BIN" "$REPO_ROOT/scripts/totpgen/main.go"
fi

# ── Build the image (or reuse it, if it matches this checkout) ─────────────
CHECKOUT_FP="$(demo_source_fingerprint "$REPO_ROOT" || true)"
IMAGE_FP=""
BUILD_REASON=""
if [ "$REBUILD" = true ]; then
  BUILD_REASON="--rebuild was given"
elif ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  BUILD_REASON="image $IMAGE_TAG does not exist"
elif [ -z "$CHECKOUT_FP" ]; then
  info "Reusing existing image $IMAGE_TAG (not a git checkout, so it cannot be compared with the source; pass --rebuild to force a fresh build)"
else
  IMAGE_FP="$(demo_image_label "$IMAGE_TAG" || true)"
  if [ "$IMAGE_FP" = "$CHECKOUT_FP" ]; then
    info "Reusing image $IMAGE_TAG: built from $IMAGE_FP, which matches this checkout"
  else
    BUILD_REASON="image $IMAGE_TAG is stale: built from ${IMAGE_FP:-an unknown source (no $DEMO_IMAGE_LABEL label: built by an older up.sh or by check.sh)}, this checkout is $CHECKOUT_FP"
  fi
fi

DEMO_RUNNING_SEEDED=false
if [ -f "$STATE_FILE" ] && docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  DEMO_RUNNING_SEEDED=true
fi

if [ -n "$BUILD_REASON" ]; then
  if [ "$NO_BUILD" = true ]; then
    echo "up.sh: $BUILD_REASON, and --no-build forbids building." >&2
    echo "       Re-run without --no-build (it rebuilds when needed), or with --rebuild to force it." >&2
    exit 1
  elif [ "$DEMO_RUNNING_SEEDED" = true ] && [ "$REBUILD" = false ]; then
    warn "$BUILD_REASON. The demo is already running from the old image, so it is left alone; to pick up this checkout run: scripts/demo/down.sh --wipe && scripts/demo/up.sh"
  else
    # `docker build -t` re-points the tag; a container another session started from
    # it would keep running the old image while the tag moves under it.
    foreign="$(docker ps --filter "ancestor=$IMAGE_TAG" --format '{{.Names}}' | grep -vx "$CONTAINER_NAME" || true)"
    if [ -n "$foreign" ] && docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
      echo "up.sh: need to rebuild $IMAGE_TAG ($BUILD_REASON), but other container(s) are running from that tag:" >&2
      echo "         ${foreign//$'\n'/, }" >&2
      echo "       Rebuilding would re-point the tag under them. Use your own names instead, e.g." >&2
      echo "       KEYORIX_DEMO_IMAGE=keyorix-demo:mine KEYORIX_DEMO_CONTAINER=keyorix-demo-mine KEYORIX_DEMO_VOLUME=keyorix-demo-mine-data KEYORIX_DEMO_PORT=8081 scripts/demo/up.sh" >&2
      exit 1
    fi
    step "Building the air-gapped image with the web UI embedded (needs network this one time): $BUILD_REASON"
    command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI (see web/package.json)" >&2; exit 1; }
    make -C "$REPO_ROOT" populate-webui-dist >/dev/null
    LABEL_ARGS=()
    [ -z "$CHECKOUT_FP" ] || LABEL_ARGS=(--label "$DEMO_IMAGE_LABEL=$CHECKOUT_FP")
    demo_stamp_build_args "$REPO_ROOT"
    docker build -f server/Dockerfile --build-arg BUILD_TAGS=noaws,noazure,nogcp \
      ${DEMO_STAMP_ARGS[@]+"${DEMO_STAMP_ARGS[@]}"} \
      ${LABEL_ARGS[@]+"${LABEL_ARGS[@]}"} -t "$IMAGE_TAG" "$REPO_ROOT" >/dev/null
    git -C "$REPO_ROOT" checkout -- server/webui/dist/index.html 2>/dev/null || true
    IMAGE_FP="$CHECKOUT_FP"
    ok "Built $IMAGE_TAG${CHECKOUT_FP:+ from $CHECKOUT_FP}"
  fi
fi

# The tamper demo in docs/demo/GOLDEN-PATH.md (section 6) edits the SQLite file
# directly, which needs a sqlite3 binary the server image does not ship. Bake it
# into a tiny helper image NOW (this is the script's online step, like the image
# build above) so the demo itself needs no `apk add` and no network on stage.
# Best-effort: without it only that one optional demo step is unavailable.
if ! docker image inspect "$SQLITE_TOOL_IMAGE" >/dev/null 2>&1; then
  step "Building the sqlite3 helper image for the tamper demo (needs network this one time)"
  if printf 'FROM alpine\nRUN apk add --no-cache sqlite\n' | docker build -t "$SQLITE_TOOL_IMAGE" - >/dev/null 2>&1; then
    ok "Built $SQLITE_TOOL_IMAGE"
  else
    warn "Could not build $SQLITE_TOOL_IMAGE (offline?). Everything else works; the tamper demo (GOLDEN-PATH section 6) needs it — re-run up.sh with network to build it."
  fi
fi

# Demo-only: the fixed master passphrase, for GOLDEN-PATH's backup/restore step,
# which references it by variable name (never the literal). Inside the
# gitignored CLI-home dir, owner-only, and removed by down.sh --wipe.
mkdir -p "$CLI_HOME"
( umask 077
  {
    echo "# DEMO ONLY — throwaway local demo credential written by scripts/demo/up.sh."
    echo "# Never reuse this value anywhere real. Source it: . $SECRETS_ENV_FILE"
    echo "KEYORIX_DEMO_MASTER_PASSWORD='$MASTER_PASSWORD'"
  } > "$SECRETS_ENV_FILE" )
chmod 600 "$SECRETS_ENV_FILE"

# ── Idempotent re-run: already seeded ──────────────────────────────────────
if [ "$DEMO_RUNNING_SEEDED" = true ]; then
  info "Demo already running and seeded — reprinting connection info"
  cat "$STATE_FILE"
  exit 0
fi

# ── Start the container (fresh or resuming an existing volume) ────────────
docker volume create "$VOLUME_NAME" >/dev/null

ALREADY_SEEDED=false
if docker run --rm -v "$VOLUME_NAME:/app/data" alpine test -f /app/data/.demo-seeded 2>/dev/null; then
  ALREADY_SEEDED=true
fi

# Seed-in-progress guard (see header): armed for a fresh seed, disarmed once
# the state file is written.
SEED_IN_PROGRESS=false
discard_unfinished_seed() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
  rm -f "$STATE_FILE"
  rm -rf "$REPO_ROOT/.demo-2-cli-home"
}
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$SEED_IN_PROGRESS" = true ]; then
    echo >&2
    echo "Demo setup failed (exit $rc). Removing the unfinished container and data volume so nothing half-seeded is left behind; fix the error above and re-run scripts/demo/up.sh." >&2
    discard_unfinished_seed
  fi
}
trap on_exit EXIT

if [ "$ALREADY_SEEDED" = false ]; then
  # A volume without the seeded marker is either brand new or left by an
  # older, interrupted run (admin created, seed never finished). The admin
  # bootstrap is one-shot, so start from an empty volume either way.
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
  docker volume rm "$VOLUME_NAME" >/dev/null
  docker volume create "$VOLUME_NAME" >/dev/null
  SEED_IN_PROGRESS=true
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
  step "Starting the air-gapped container (network enabled for the demo itself; see docs/demo/GOLDEN-PATH.md for the offline proof with --network none)"
  docker run -d --name "$CONTAINER_NAME" \
    -p "${PORT}:8080" \
    -v "$VOLUME_NAME:/app/data" \
    -w /app/data \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PASSWORD" \
    -e KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
    -e KEYORIX_CONFIG_PATH=keyorix.yaml \
    --entrypoint /bin/sh \
    "$IMAGE_TAG" \
    -c '
      set -e
      if [ ! -f keyorix.yaml ]; then
        # Local demo over plain HTTP: the relaxed, DEV-ONLY-labelled config.
        /app/keyorix-server admin init --dev --config keyorix.yaml
        /app/keyorix-server admin encryption init --config keyorix.yaml
        /app/keyorix-server admin migrate --config keyorix.yaml
        # Break-glass is off by default (secure default); the demo turns it on
        # explicitly so `keyorix break-glass activate` works (#2943).
        printf "\nbreak_glass:\n  enabled: true\n  emergency_role: project_developer\n  default_ttl: 4h\n  max_ttl: 24h\n" >> keyorix.yaml
      fi
      # The server binds 127.0.0.1 by default (#2939); inside the container it
      # must listen on all interfaces for the published -p port to work. Done on
      # every start (not only on creation) so demo volumes created before that
      # change are fixed too, and it fails loudly if the insert did not land.
      if ! grep -q "^    host: \"0.0.0.0\"" keyorix.yaml; then
        sed -i "s|^    port: \"8080\"|    host: \"0.0.0.0\"\n    port: \"8080\"|" keyorix.yaml
        if ! grep -q "^    host: \"0.0.0.0\"" keyorix.yaml; then
          echo "up.sh: could not set server.http.host to 0.0.0.0 in keyorix.yaml (no 4-space-indented port: \"8080\" line to anchor on); the published port would not work" >&2
          exit 1
        fi
      fi
      exec /app/keyorix-server
    ' >/dev/null
  ok "Container started"
fi

step "Waiting for the server to be healthy"
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://localhost:${PORT}/health"; then
    ok "Server is healthy"
    break
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
    echo "Container $CONTAINER_NAME exited during startup (log tail above)" >&2
    started_fp="$(demo_image_label "$IMAGE_TAG" || true)"
    if [ -n "$CHECKOUT_FP" ] && [ "$started_fp" != "$CHECKOUT_FP" ]; then
      echo "Likely cause: image $IMAGE_TAG was built from ${started_fp:-an unknown source}, but this checkout is $CHECKOUT_FP. Re-run with --rebuild." >&2
    fi
    exit 1
  fi
  sleep 1
done

if [ "$ALREADY_SEEDED" = true ]; then
  info "Data volume already seeded from a previous run — skipping seed, container just (re)started"
  if [ -f "$STATE_FILE" ]; then
    cat "$STATE_FILE"
  else
    warn "No local state file found (was it deleted?) — the demo data exists but its printed credentials are lost. Run scripts/demo/down.sh --wipe and up.sh again for a clean, fully-printed run."
  fi
  exit 0
fi

export HOME="$REPO_ROOT/.demo-2-cli-home"
mkdir -p "$HOME"
rm -f "$HOME/.keyorix/cli.yaml" 2>/dev/null || true

SERVER_URL="http://localhost:${PORT}"

step "Bootstrapping the admin account (public API, via 'keyorix system init')"
# Credentials travel in the environment (KEYORIX_ADMIN_PASSWORD / _BOOTSTRAP_TOKEN),
# never as flags, so the CLI prints no "insecure on the command line" warnings.
KEYORIX_ADMIN_PASSWORD="$ADMIN_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
  "$CLI_BIN" system init --server "$SERVER_URL" \
  --admin-username "$ADMIN_USER" --admin-email "$ADMIN_EMAIL" >/dev/null
ok "Admin bootstrapped"

# security.require_mfa is ON (the secure default, kept for the demo): until the
# admin enrols, every call except MFA enrolment is refused with HTTP 403. The
# enrolment itself is shared with check.sh (scripts/demo/lib.sh, #3034).
step "Enrolling TOTP for the demo admin (multi-factor authentication is required)"
demo_enroll_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" || { echo "MFA enrolment failed (see above)" >&2; exit 1; }
MFA_SECRET="$DEMO_MFA_SECRET"
MFA_URI="$DEMO_MFA_URI"
RECOVERY_CODES="$DEMO_RECOVERY_CODES"

echo
echo -e "${YELLOW}  >>> ADD THIS TO YOUR AUTHENTICATOR APP NOW (shown once; the web login asks for a code) <<<${NC}"
echo "      Setup key (manual entry): $MFA_SECRET"
echo "      otpauth URI:              $MFA_URI"
if command -v qrencode >/dev/null 2>&1; then
  qrencode -t ANSIUTF8 "$MFA_URI"
else
  echo "      (install 'qrencode' to get a scannable QR code here; otherwise type the setup key in by hand)"
fi
[ -z "$RECOVERY_CODES" ] || echo "      Recovery codes (one use each): $RECOVERY_CODES"
echo

# The CLI authenticates from the environment from here on (session obtained by
# the code login above); no stored password, no --password flags.
export KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$DEMO_TOKEN"
# check.sh asks for this session (KEYORIX_DEMO_SESSION_OUT=<file>) so its admin
# checks don't spend two more of the 10-per-15-minute login attempts (#2956) on an
# identical MFA login. Only written on request; 0600; check.sh deletes it.
if [ -n "${KEYORIX_DEMO_SESSION_OUT:-}" ]; then
  ( umask 077; printf '%s' "$DEMO_TOKEN" > "$KEYORIX_DEMO_SESSION_OUT" )
fi
# Demo only, 0600, removed by down.sh --wipe with the rest of CLI_HOME: lets the
# CI seed check reuse this session instead of spending two more slots of the
# per-IP login budget (10 per 15 min, each login AND each MFA verify counts).
( umask 077; printf '%s' "$DEMO_TOKEN" > "$CLI_HOME/.admin-session-token" )
ok "Admin MFA enrolled (TOTP) and logged in with a code"

step "Seeding org structure: 2 projects, 2 groups"
"$CLI_BIN" project create --name backend-api --description "Backend API" >/dev/null
"$CLI_BIN" project create --name mobile-app --description "Mobile App" >/dev/null
# A global role makes nobody a member of any project, and only an owner who is a
# member of the secret's project may share it (#2976). Make the admin a member of
# backend-api so the demo's share step works on db-password.
"$CLI_BIN" rbac assign-role --user "$ADMIN_EMAIL" --role project_admin --project backend-api >/dev/null
"$CLI_BIN" group create --name platform-team --description "Platform team" >/dev/null
"$CLI_BIN" group create --name mobile-team --description "Mobile team" >/dev/null
ok "3 projects (default, backend-api, mobile-app), 2 groups; admin is project_admin on backend-api"

step "Seeding a least-privilege user"
KEYORIX_INITIAL_PASSWORD="$ALICE_PASSWORD" "$CLI_BIN" user create --username alice --email alice@keyorix.demo >/dev/null
"$CLI_BIN" rbac assign-role --user alice@keyorix.demo --role project_viewer --project backend-api >/dev/null
ok "alice: project_viewer on backend-api only"

# A healthy fresh posture needs 100% second-factor coverage (control
# second-factor), so alice is enrolled here, like the admin, and gets one real
# read below (a grant nobody ever used is a "dormant access" gap). The live
# enrolment moment of docs/demo/GOLDEN-PATH.md section 2 uses a brand-new user.
step "Enrolling TOTP for alice (every seeded account has a second factor)"
demo_enroll_mfa "$SERVER_URL" alice "$ALICE_PASSWORD" || { echo "alice MFA enrolment failed (see above)" >&2; exit 1; }
ALICE_MFA_SECRET="$DEMO_MFA_SECRET"
ALICE_MFA_URI="$DEMO_MFA_URI"
ALICE_RECOVERY_CODES="$DEMO_RECOVERY_CODES"
ALICE_TOKEN="$DEMO_TOKEN"
ok "alice enrolled"

# The independent reviewer: with a single global admin, break-glass activations
# can never be reviewed by anyone but their activator, which the control matrix
# (rightly) reports as a gap. A second administrator, security-officer, is the
# separate approver a real deployment has.
step "Seeding a second administrator (independent break-glass reviewer)"
KEYORIX_INITIAL_PASSWORD="$SECOFFICER_PASSWORD" "$CLI_BIN" user create --username security-officer --email security-officer@keyorix.demo >/dev/null
"$CLI_BIN" rbac assign-role --user security-officer@keyorix.demo --role admin >/dev/null
demo_enroll_mfa "$SERVER_URL" security-officer "$SECOFFICER_PASSWORD" || { echo "security-officer MFA enrolment failed (see above)" >&2; exit 1; }
SECOFFICER_MFA_SECRET="$DEMO_MFA_SECRET"
SECOFFICER_MFA_URI="$DEMO_MFA_URI"
SECOFFICER_RECOVERY_CODES="$DEMO_RECOVERY_CODES"
SECOFFICER_TOKEN="$DEMO_TOKEN"
ok "security-officer: admin, TOTP enrolled"

step "Seeding secrets with versions"
# Values go in via a relative file / stdin, never --value (which warns).
seed_value_file="$CLI_HOME/.seed-value"
create_secret() { # create_secret NAME VALUE PROJECT_ID ENVIRONMENT_ID
  ( umask 077; printf '%s' "$2" > "$seed_value_file" )
  "$CLI_BIN" secret create --name "$1" --from-file ".demo-2-cli-home/.seed-value" --project "$3" --environment "$4" >/dev/null
  rm -f "$seed_value_file"
}
create_secret "stripe-api-key" "sk_test_demo_seed_v1" 1 1
# rotate has no file flag; its stdin prompt writes "New secret value (hidden):" to
# stderr, so keep stderr out of the presenter's output unless the command fails.
printf '%s\n' "sk_test_demo_seed_v2" | "$CLI_BIN" secret rotate --id 1 >/dev/null 2>"$CLI_HOME/.rotate-err" \
  || { cat "$CLI_HOME/.rotate-err" >&2; exit 1; }
rm -f "$CLI_HOME/.rotate-err"
create_secret "db-password" "demo-db-pass-v1" 2 4
# The Secrets tab opens on Production: seed one there too so the presenter's
# first view of backend-api is not empty (DEMO-WALK-3 finding 36).
create_secret "payments-webhook-secret" "whsec_demo_seed_v1" 2 6
ok "3 secrets (one with 2 versions); backend-api has one in Development and one in Production"

# Every secret carries a data-classification label (ISO 27001 A.5.12), so the
# "Secret data classification" control starts green.
for sid in 1 2 3; do
  "$CLI_BIN" secret classify --id "$sid" --level confidential >/dev/null
done

# Rotation policies (A.5.15). The two long-standing secrets are covered; the
# Production webhook secret deliberately is NOT. That one uncovered production
# secret is the demo's single, deliberate finding (the "Secret-rotation hygiene"
# control shows "2 of 3 secrets covered") and GOLDEN-PATH.md section 1b fixes it
# live. Everything else on the Compliance page is green on a fresh demo.
step "Seeding rotation policies (one production secret deliberately left uncovered)"
"$CLI_BIN" rotation create --name "default-90d" --scope project --project-id 1 --interval-days 90 >/dev/null
"$CLI_BIN" rotation create --name "backend-api-dev-90d" --scope environment --environment-id 4 --interval-days 90 >/dev/null
ok "stripe-api-key and db-password are on a 90-day rotation; payments-webhook-secret (Production) has no policy"

step "Seeding a machine identity"
"$CLI_BIN" machine create --name ci-app --project default --type ci --classification internal >/dev/null
"$CLI_BIN" machine grant-role ci-app --project default --role project_viewer >/dev/null
MACHINE_TOKEN_OUTPUT="$("$CLI_BIN" machine token issue ci-app --name "ci-pipeline-token" --project default --classification internal)"
MACHINE_TOKEN="$(echo "$MACHINE_TOKEN_OUTPUT" | grep -oE 'kx_machine_[A-Za-z0-9_-]+' | head -1)"
ok "ci-app machine identity, project_viewer on default"

step "Populating an audit trail (reveal + rotate + a machine read already happened above)"
"$CLI_BIN" secret get --id 1 --show-value >/dev/null
curl -s -H "Authorization: Bearer $MACHINE_TOKEN" "http://localhost:${PORT}/api/v1/secrets/1?include_value=true" >/dev/null
demo_api GET "$SERVER_URL" "/api/v1/secrets/value?ref=backend-api%2Fdevelopment%2Fdb-password" "$ALICE_TOKEN"
[ "$DEMO_HTTP_CODE" = "200" ] || { echo "alice could not read backend-api/development/db-password ($DEMO_HTTP_CODE): $DEMO_BODY" >&2; exit 1; }
ok "Audit trail populated — 'keyorix audit logs' now has real events to show"

# Access review (A.5.18): one completed recertification campaign per project,
# every seeded grant attested by the admin, so "Access recertification" starts
# green. Done last so the campaigns snapshot the final set of grants.
step "Running the first access-review campaign for each project"
for pid in 1 2 3; do
  demo_review_project "$SERVER_URL" "$KEYORIX_TOKEN" "$SECOFFICER_TOKEN" "$pid" "Initial access review" "Initial demo access review: grant is expected" \
    || { echo "access review of project $pid failed (see above)" >&2; exit 1; }
done
ok "3 projects reviewed and closed"

docker exec "$CONTAINER_NAME" touch /app/data/.demo-seeded
SEED_IN_PROGRESS=false

cat > "$STATE_FILE" <<EOF
======================================================================
  Keyorix air-gapped demo is up.

  URL:            $SERVER_URL
  Admin login:    $ADMIN_USER / $ADMIN_PASSWORD   + a 6-digit code (MFA is required)
  Admin TOTP key: $MFA_SECRET
                  $MFA_URI
  Recovery codes: $RECOVERY_CODES
  Alice login:    alice / $ALICE_PASSWORD   + a 6-digit code (least-privilege: backend-api only)
  Alice TOTP key: $ALICE_MFA_SECRET
                  $ALICE_MFA_URI
  Alice recovery: $ALICE_RECOVERY_CODES
  Second admin:   security-officer / $SECOFFICER_PASSWORD   + a 6-digit code
                  (the independent break-glass reviewer)
  Officer TOTP:   $SECOFFICER_MFA_SECRET
                  $SECOFFICER_MFA_URI
  Officer recovery: $SECOFFICER_RECOVERY_CODES
  Machine token:  $MACHINE_TOKEN
                  (ci-app, project_viewer on default — shown once, saved here)
  Master passphrase (for the backup/restore step): DEMO-only, in
                  .demo-2-cli-home/demo-secrets.env as KEYORIX_DEMO_MASTER_PASSWORD

  scripts/demo/down.sh to stop (keeps data); add --wipe to delete it.
======================================================================
EOF
cat "$STATE_FILE"
