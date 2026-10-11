#!/usr/bin/env bash
# scripts/airgap-e2e.sh -- end-to-end disaster-recovery drill for
# `keyorix-server admin backup`/`admin restore` (ADR-108 B3) plus the
# air-gapped audit-chain anchor workflow (design-b4-offline-audit-verify.md),
# run entirely inside a container with --network none: nothing here ever
# needs internet access, matching the single-machine/air-gapped deployment
# this product is positioned on (see server/entrypoint.sh's own doc comment
# for the same "no server needed for the embedded/CLI path" framing --
# this script is the equivalent proof for the server binary's admin path).
#
# MANUAL target only (not run in CI -- see `make airgap-e2e`, added by the
# CLI-RELEASE track): needs Docker or Podman, spins up real containers, and
# takes tens of seconds because it waits out a real audit-checkpoint
# interval. CI already covers the unit/integration/fuzz layer for backup and
# restore (server/admin/backup_restore_*_test.go) -- this script proves the
# parts that need a real container boundary: a genuinely fresh key-material
# generation, a real HTTP-driven admin bootstrap + secret write, and the
# admin backup/restore round trip preserving both the secret VALUE and the
# audit hash chain, cross-checked against an externally-held checkpoint
# anchor exactly the way an operator holding write-once media would.
#
# Flow:
#   1. Build the keyorix-server image (or reuse KEYORIX_AIRGAP_E2E_IMAGE).
#   2. Boot it with --network none, bootstrap the first admin user, create a
#      project + secret over the HTTP API (via `docker exec` + busybox wget
#      hitting the container's own loopback -- never the host network), wait
#      out one audit-checkpoint interval, stop the server (admin commands
#      refuse to run against a live server's database), export that
#      checkpoint to a file OUTSIDE the container (the host work dir stands
#      in for write-once media held off-host), then `admin backup`.
#   3. Restore the archive into a FRESH data directory in a second
#      container, run `admin verify-audit --anchor <the externally-held
#      export>` against the restored database, then boot a third short-lived
#      server against the restored data and read the secret back over the
#      API -- asserting both the audit chain and the secret VALUE survived.
#   4. Negative leg: flip one byte in a copy of the archive and confirm
#      `admin restore` refuses it (non-zero exit) instead of silently
#      accepting corrupted input.
#
# Every admin/server invocation below runs `--network none`; only
# `docker exec`/`podman exec` against the container's own loopback is used
# to drive the HTTP API, so a real port is never published to the host.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "" >&2
    echo "AIRGAP E2E FAILED: $1" >&2
    exit 1
}

# --- 1. engine detection: skip cleanly, never fail the caller, if neither
# Docker nor Podman is available -- this is a manual drill, not a hard
# dependency of the build. ---
ENGINE=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ENGINE=docker
elif command -v podman >/dev/null 2>&1; then
    ENGINE=podman
else
    echo "Docker/Podman not available -- skipping the air-gap E2E drill (nothing to verify without a container engine)."
    exit 0
fi
echo "==> Using container engine: $ENGINE"

command -v jq >/dev/null 2>&1 || fail "jq is required to parse the HTTP API responses this script drives -- install jq and re-run"

IMAGE="${KEYORIX_AIRGAP_E2E_IMAGE:-keyorix-server:airgap-e2e}"
RUN_ID="airgap-e2e-$$"
# Only the two long-lived (`docker run -d`) containers need names to clean up
# -- every admin/verify/export/negative-leg invocation below uses
# `--rm`, so it never leaves a container behind to track here.
SERVER_CONTAINER="${RUN_ID}-server"
RESTORE_CONTAINER="${RUN_ID}-restore"

WORK_DIR="$(mktemp -d)"
SRC_DIR="$WORK_DIR/src"          # bind-mounted into the ORIGINAL server (/app/data)
DST_DIR="$WORK_DIR/dst"          # bind-mounted into the RESTORE target (/app/data)
NEG_DIR="$WORK_DIR/neg"          # bind-mounted into the negative-leg restore target
EXTERNAL_DIR="$WORK_DIR/external-media"  # stands in for write-once media held OFF this host
mkdir -p "$SRC_DIR/keys" "$DST_DIR" "$NEG_DIR" "$EXTERNAL_DIR"

cleanup() {
    $ENGINE rm -f "$SERVER_CONTAINER" "$RESTORE_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "==> Work dir: $WORK_DIR"

# --- 2. build the image (skip if the caller already provided one) ---
if [ -z "${KEYORIX_AIRGAP_E2E_IMAGE:-}" ]; then
    echo "==> Building $IMAGE from server/Dockerfile"
    $ENGINE build -q -f "$REPO_ROOT/server/Dockerfile" -t "$IMAGE" "$REPO_ROOT" >/dev/null
fi

# --- secrets for this run only, generated locally, never logged ---
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
MASTER_PW="airgap-e2e-master-$(rand_hex 24)"
ADMIN_PW="Airgap-E2E-Drill-1!$(rand_hex 8)"   # satisfies the default password policy (16+, mixed case, digit, special)
BOOTSTRAP_TOKEN="$(rand_hex 24)"
ADMIN_USER="airgap-admin"
ADMIN_EMAIL="airgap-admin@keyorix.invalid"
SECRET_NAME="airgap-e2e-secret"
SECRET_VALUE="airgap-e2e-value-$(rand_hex 12)"

# --- 3. minimal config: RELATIVE db/key paths (internal/keyfiles.SafePath
# and encryption.Service both reject absolute ones outright), resolved
# against --workdir /app/data on every container invocation below so they
# always land in the mounted data dir regardless of the image's own
# /app-rooted default. A short audit-checkpoint schedule means this drill
# doesn't need to wait out a real 24h default; everything else is left at
# the built-in Go zero-value defaults (session/password_policy/purge/
# soft_delete/membership all document themselves as safe to omit). ---
cat >"$SRC_DIR/keyorix.yaml" <<EOF
server:
  http:
    enabled: true
    port: "8080"
storage:
  type: sqlite
  database:
    path: keyorix.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
audit_checkpoints:
  schedule: "3s"
# ADR-112 item 1: security.require_mfa defaults on, which would confine the
# bootstrap admin's session to the MFA-enrolment endpoints
# (EnforceAccountSetup) until it enrols -- blocking the secret create/read
# calls below. scripts/smoke.sh and the release-qa scenarios enrol for real
# via the CLI's \`mfa enroll\`/\`mfa activate\`; this script drives the raw
# HTTP API with wget/jq instead of the CLI (see this file's own header: it
# proves the admin backup/restore round trip inside a --network none
# container, not the CLI), and has no dependency-free way to compute a TOTP
# code from inside that container. Opt out visibly (not silently) rather
# than add a new host/image dependency just to simulate an authenticator app.
security:
  require_mfa: false
EOF

# --- exec helpers: every HTTP call goes through the container's own
# loopback via `exec`, never a published port -- --network none never has to
# come off. ---
api_get() {
    # api_get <container> <path> [bearer-token]
    local container="$1" path="$2" token="${3:-}"
    if [ -n "$token" ]; then
        $ENGINE exec "$container" wget -q --header="Authorization: Bearer $token" -O- "http://127.0.0.1:8080$path"
    else
        $ENGINE exec "$container" wget -q -O- "http://127.0.0.1:8080$path"
    fi
}

api_post() {
    # api_post <container> <path> <mounted-payload-path> [bearer-token]
    # The mounted path must already hold valid JSON (the caller writes it to
    # the bind-mounted host file first, e.g. via `jq -n > "$SRC_DIR/x.json"`)
    # -- this only POSTs it, it does not build it.
    local container="$1" path="$2" mounted_path="$3" token="${4:-}"
    if [ -n "$token" ]; then
        $ENGINE exec "$container" wget -q --header="Content-Type: application/json" \
            --header="Authorization: Bearer $token" --post-file="$mounted_path" -O- "http://127.0.0.1:8080$path"
    else
        $ENGINE exec "$container" wget -q --header="Content-Type: application/json" \
            --post-file="$mounted_path" -O- "http://127.0.0.1:8080$path"
    fi
}

wait_for_health() {
    local container="$1"
    for _ in $(seq 1 30); do
        if $ENGINE exec "$container" wget -q --spider "http://127.0.0.1:8080/health" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    fail "$container never became healthy on http://127.0.0.1:8080/health"
}

# ============================================================================
# Positive leg: real server, real data, backup, restore, verify.
# ============================================================================

echo "==> Starting the source server (--network none, loopback only)"
$ENGINE run -d --name "$SERVER_CONTAINER" --network none --workdir /app/data \
    -v "$SRC_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    -e KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" >/dev/null
wait_for_health "$SERVER_CONTAINER"

echo "==> Bootstrapping the first admin user + default project (POST /system/init)"
jq -n --arg u "$ADMIN_USER" --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PW" --arg t "$BOOTSTRAP_TOKEN" \
    '{username: $u, email: $e, password: $p, bootstrap_token: $t}' >"$SRC_DIR/init-payload.json"
INIT_OUT="$($ENGINE exec "$SERVER_CONTAINER" wget -q --header="Content-Type: application/json" \
    --post-file=/app/data/init-payload.json -O- "http://127.0.0.1:8080/system/init")" || fail "POST /system/init failed"
echo "$INIT_OUT" | jq -e '.data.user.id' >/dev/null || fail "system/init did not return a user id: $INIT_OUT"

echo "==> Logging in as $ADMIN_USER"
LOGIN_PAYLOAD="$SRC_DIR/login-payload.json"
jq -n --arg u "$ADMIN_USER" --arg p "$ADMIN_PW" '{username: $u, password: $p}' >"$LOGIN_PAYLOAD"
LOGIN_OUT="$($ENGINE exec "$SERVER_CONTAINER" wget -q --header="Content-Type: application/json" \
    --post-file=/app/data/login-payload.json -O- "http://127.0.0.1:8080/auth/login")" || fail "POST /auth/login failed"
TOKEN="$(echo "$LOGIN_OUT" | jq -r '.data.token')"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login did not return a session token: $LOGIN_OUT"

# jq lookups below try both `id` and `ID`: some handlers return a
# purpose-built response DTO (lowercase, matching openapi.yaml -- e.g.
# POST /system/init's `data.user.id`), others return a raw GORM model
# straight through (defaults to the exported Go field name, `ID`) -- found
# live while writing this script; HANDOFF -> API in the BACKUP track report.
echo "==> Resolving the default project + environment created by system/init"
PROJECTS_OUT="$(api_get "$SERVER_CONTAINER" "/api/v1/projects" "$TOKEN")" || fail "GET /api/v1/projects failed"
PROJECT_ID="$(echo "$PROJECTS_OUT" | jq -r '.data.projects[0].id // .data.projects[0].ID')"
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "null" ] || fail "no default project found: $PROJECTS_OUT"
ENVS_OUT="$(api_get "$SERVER_CONTAINER" "/api/v1/projects/$PROJECT_ID/environments" "$TOKEN")" || fail "GET environments failed"
ENV_ID="$(echo "$ENVS_OUT" | jq -r '.data.environments[0].id // .data.environments[0].ID')"
[ -n "$ENV_ID" ] && [ "$ENV_ID" != "null" ] || fail "no default environment found: $ENVS_OUT"

echo "==> Creating a real secret ($SECRET_NAME)"
SECRET_PAYLOAD="$SRC_DIR/secret-payload.json"
jq -n --arg name "$SECRET_NAME" --arg value "$SECRET_VALUE" --argjson pid "$PROJECT_ID" --argjson eid "$ENV_ID" \
    '{name: $name, value: $value, project_id: $pid, environment_id: $eid, type: "generic"}' >"$SECRET_PAYLOAD"
CREATE_OUT="$(api_post "$SERVER_CONTAINER" "/api/v1/secrets" "/app/data/secret-payload.json" "$TOKEN")" || fail "POST /api/v1/secrets failed"
SECRET_ID="$(echo "$CREATE_OUT" | jq -r '.data.id // .data.ID')"
[ -n "$SECRET_ID" ] && [ "$SECRET_ID" != "null" ] || fail "secret create did not return an id: $CREATE_OUT"

echo "==> Waiting out one audit-checkpoint interval so a signed checkpoint exists to export"
sleep 6

echo "==> Stopping the source server (admin commands refuse to run against a live server's database -- serverguard)"
$ENGINE stop "$SERVER_CONTAINER" >/dev/null
$ENGINE rm "$SERVER_CONTAINER" >/dev/null

echo "==> Exporting the checkpoint to $EXTERNAL_DIR (stands in for write-once media held off this host)"
$ENGINE run --rm --network none --workdir /app/data \
    -v "$SRC_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    --entrypoint /app/keyorix-server \
    "$IMAGE" admin --config /app/data/keyorix.yaml audit export-checkpoint --output /app/data/checkpoint-export.json >/dev/null \
    || fail "admin audit export-checkpoint failed"
cp "$SRC_DIR/checkpoint-export.json" "$EXTERNAL_DIR/checkpoint-export.json"
[ -s "$EXTERNAL_DIR/checkpoint-export.json" ] || fail "checkpoint export is empty"

echo "==> admin backup (--network none)"
$ENGINE run --rm --network none --workdir /app/data \
    -v "$SRC_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" admin --config /app/data/keyorix.yaml backup --output /app/data/backup.tar.gz \
    || fail "admin backup failed"
[ -s "$SRC_DIR/backup.tar.gz" ] || fail "admin backup did not produce an archive"
cp "$SRC_DIR/backup.tar.gz" "$WORK_DIR/backup.tar.gz"

echo "==> admin restore into a FRESH data directory (--network none)"
cat >"$DST_DIR/keyorix.yaml" <<EOF
server:
  http:
    enabled: true
    port: "8080"
storage:
  type: sqlite
  database:
    path: keyorix.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
audit_checkpoints:
  schedule: "3s"
# ADR-112 item 1 -- see the identical override + comment on \$SRC_DIR's
# config above; the restored admin here never enrolled MFA either.
security:
  require_mfa: false
EOF
cp "$WORK_DIR/backup.tar.gz" "$DST_DIR/backup.tar.gz"
$ENGINE run --rm --network none --workdir /app/data \
    -v "$DST_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" admin --config /app/data/keyorix.yaml restore --input /app/data/backup.tar.gz \
    || fail "admin restore (positive leg) failed"

echo "==> admin verify-audit against the restored database, cross-checked against the externally-held anchor"
cp "$EXTERNAL_DIR/checkpoint-export.json" "$DST_DIR/checkpoint-export.json"
VERIFY_OUT="$($ENGINE run --rm --network none --workdir /app/data \
    -v "$DST_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    --entrypoint /app/keyorix-server \
    "$IMAGE" admin --config /app/data/keyorix.yaml verify-audit --json \
        --anchor /app/data/checkpoint-export.json)" || fail "admin verify-audit (restored db) failed: $VERIFY_OUT"
echo "$VERIFY_OUT" | jq -e '.verdict == "VALID"' >/dev/null \
    || fail "verify-audit on the restored database did not report VALID: $VERIFY_OUT"
echo "$VERIFY_OUT" | jq -e '.external_anchor.supplied == true' >/dev/null \
    || fail "verify-audit did not report the external anchor as supplied: $VERIFY_OUT"
echo "    verify-audit: VALID, external anchor cross-checked"

echo "==> Booting a server against the RESTORED data to confirm the secret VALUE survived"
$ENGINE run -d --name "$RESTORE_CONTAINER" --network none --workdir /app/data \
    -v "$DST_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" >/dev/null
wait_for_health "$RESTORE_CONTAINER"

RESTORE_LOGIN_PAYLOAD="$DST_DIR/login-payload.json"
jq -n --arg u "$ADMIN_USER" --arg p "$ADMIN_PW" '{username: $u, password: $p}' >"$RESTORE_LOGIN_PAYLOAD"
RESTORE_LOGIN_OUT="$($ENGINE exec "$RESTORE_CONTAINER" wget -q --header="Content-Type: application/json" \
    --post-file=/app/data/login-payload.json -O- "http://127.0.0.1:8080/auth/login")" || fail "login against restored server failed"
RESTORE_TOKEN="$(echo "$RESTORE_LOGIN_OUT" | jq -r '.data.token')"
[ -n "$RESTORE_TOKEN" ] && [ "$RESTORE_TOKEN" != "null" ] || fail "restored server login did not return a token: $RESTORE_LOGIN_OUT"

GOT_SECRET_OUT="$(api_get "$RESTORE_CONTAINER" "/api/v1/secrets/$SECRET_ID?include_value=true" "$RESTORE_TOKEN")" \
    || fail "GET restored secret failed"
GOT_VALUE="$(echo "$GOT_SECRET_OUT" | jq -r '.data.value // .data.Value')"
[ "$GOT_VALUE" = "$SECRET_VALUE" ] || fail "restored secret value mismatch: got $(printf '%q' "$GOT_VALUE"), want $(printf '%q' "$SECRET_VALUE")"
echo "    secret value round-tripped correctly through backup + restore"

$ENGINE stop "$RESTORE_CONTAINER" >/dev/null
$ENGINE rm "$RESTORE_CONTAINER" >/dev/null

# ============================================================================
# Negative leg: a corrupted archive must be refused, never silently accepted.
# ============================================================================

echo "==> Negative leg: flipping one byte in a copy of the archive"
cp "$WORK_DIR/backup.tar.gz" "$NEG_DIR/backup.tar.gz"
# Flip a byte in the MIDDLE of the file, not the very last one: archive/tar's
# Next() stops as soon as it sees the two-zero-block end-of-archive marker,
# without necessarily reading the underlying gzip stream all the way to ITS
# own true end -- so corrupting only gzip's trailing CRC32/ISIZE bytes (the
# tail of the file) is never actually read back and silently goes
# undetected, a gap in the file's own trailer region only, not in any real
# entry's content. A byte inside the actual compressed entry data is always
# read (it lands within one of the tar entries tr.Next()/io.ReadAll consume)
# and reliably breaks either DEFLATE decoding or the entry's SHA-256 check.
python3 - "$NEG_DIR/backup.tar.gz" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:
    f.seek(0, 2)
    size = f.tell()
    offset = size // 2
    f.seek(offset)
    b = f.read(1)
    f.seek(offset)
    f.write(bytes([b[0] ^ 0xFF]))
PYEOF

cat >"$NEG_DIR/keyorix.yaml" <<EOF
server:
  http:
    enabled: true
    port: "8080"
storage:
  type: sqlite
  database:
    path: keyorix.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
audit_checkpoints:
  schedule: "3s"
EOF

set +e
$ENGINE run --rm --network none --workdir /app/data \
    -v "$NEG_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" admin --config /app/data/keyorix.yaml restore --input /app/data/backup.tar.gz
NEG_STATUS=$?
set -e
[ "$NEG_STATUS" -ne 0 ] || fail "admin restore accepted a tampered archive (exit 0) -- expected a non-zero exit"
echo "    tampered archive correctly refused (exit $NEG_STATUS)"

echo ""
echo "AIRGAP E2E PASSED"
