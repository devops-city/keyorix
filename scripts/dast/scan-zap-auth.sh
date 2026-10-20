#!/usr/bin/env bash
# scan-zap-auth.sh — authenticated ZAP API scan passes: (a) regular user
# ("viewer", lowest privilege) and (b) admin. Complements scan-zap.sh's
# anonymous baseline. Requires provision-testuser.sh to have been run once.
#
# Tokens are minted fresh at the start of this run by logging in as the
# already-bootstrapped admin and the provisioned viewer account. They exist
# only as in-memory shell variables and short-lived container env vars for
# the duration of this run — never written to results/. The one caveat: the
# admin/user token is passed to `docker run` as a ZAP replacer config value,
# so it is visible in that container's own argv (`docker inspect`/`ps`) for
# its lifetime — the container is --rm and gone within minutes, and no
# persisted file (report, JSON, or coverage log) ever contains it.
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOCKFILE="$WORKDIR/dast.lock"
HB_LOG="$WORKDIR/results/heartbeat.log"
START_TS="$(date -u +%FT%TZ)"
SCAN_SHA=""

if [ -f "$WORKDIR/.env" ]; then
    # shellcheck source=/dev/null
    set -a; . "$WORKDIR/.env"; set +a
fi
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"
# shellcheck source=/dev/null
. "$WORKDIR/lib-http.sh"

record_heartbeat() {
    local rc=$?
    echo "$(date -u +%FT%TZ) scan=zap-auth start=$START_TS end=$(date -u +%FT%TZ) exit=$rc sha=${SCAN_SHA:-unknown}" >> "$HB_LOG"
}
trap record_heartbeat EXIT

mkdir -p "$WORKDIR/results"
chmod 777 "$WORKDIR/results"

# Exclusive lock — same rig, same rules as the anonymous passes.
exec 9>"$LOCKFILE"
flock -x 9

SCAN_SHA="$("$WORKDIR/refresh-src.sh")"

: "${KEYORIX_ADMIN_USERNAME:?}"
: "${KEYORIX_ADMIN_PASSWORD:?}"
: "${KEYORIX_TESTUSER_USERNAME:?run provision-testuser.sh once first}"
: "${KEYORIX_TESTUSER_PASSWORD:?run provision-testuser.sh once first}"

mint_token() {
    local user="$1" pass="$2"
    dast_post_json http://localhost:8080/auth/login \
        "{\"username\":\"$user\",\"password\":\"$pass\"}" -sf \
        2>/dev/null | jq -r '.data.token // empty'
}

ADMIN_TOKEN="$(mint_token "$KEYORIX_ADMIN_USERNAME" "$KEYORIX_ADMIN_PASSWORD")"
USER_TOKEN="$(mint_token "$KEYORIX_TESTUSER_USERNAME" "$KEYORIX_TESTUSER_PASSWORD")"

if [ -z "$ADMIN_TOKEN" ] || [ -z "$USER_TOKEN" ]; then
    dast_alert "could not mint auth token(s) for authenticated ZAP passes (admin_ok=$([ -n "$ADMIN_TOKEN" ] && echo yes || echo no) user_ok=$([ -n "$USER_TOKEN" ] && echo yes || echo no))"
    exit 1
fi

run_authenticated_pass() {
    local label="$1" token="$2"
    local report="$WORKDIR/results/zap-$label-$TIMESTAMP-$SCAN_SHA.html"
    echo "[$(date -u +%FT%TZ)] Starting ZAP API scan as $label (sha=$SCAN_SHA) -> $report"
    # No --hook: see scan-zap.sh's comment -- 100001 suppression now lives in
    # accepted-exceptions.yaml, applied post-scan by create-issues.sh.
    #
    # KNOWN GAP (SCRIPTS-SECRETS-2): the -z string below carries the principal's bearer token, so
    # it is visible in `ps` on this host for the length of the scan. It is the one argv secret
    # left under scripts/dast; the cli guard (TestDocsShowNoLiteralSecretOnCommandLine) cannot see it
    # because the token is interpolated from a variable. Moving it into a ZAP properties file
    # (`-z "-configfile ..."`) needs the file readable by the container's zap uid and a run on the
    # DAST host to confirm, so it is not done blind.
    docker run --rm \
      --pull never \
      --network keyorix-dast_default \
      -v "$WORKDIR/results:/zap/wrk" \
      keyorix-scanner:latest \
      zap-api-scan.py \
      -t http://keyorix:8080/openapi.yaml \
      -f openapi \
      -r "$(basename "$report")" \
      -J "zap-$label-$TIMESTAMP-$SCAN_SHA.json" \
      -z "-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer\\ $token" \
      -I || true
    echo "[$(date -u +%FT%TZ)] ZAP $label pass done -> $report"
    if [ -x "$WORKDIR/create-issues.sh" ]; then
        "$WORKDIR/create-issues.sh" "-" "$WORKDIR/results/zap-$label-$TIMESTAMP-$SCAN_SHA.json"
    fi
}

run_authenticated_pass "user" "$USER_TOKEN"
run_authenticated_pass "admin" "$ADMIN_TOKEN"

# ── Coverage comparison ──────────────────────────────────────────────────
# "Non-401" per principal across every declared /api/v1/* (method, path)
# operation -- the actual protected surface. ZAP's own JSON report is
# alert-centric (only endpoints that triggered a finding appear) so it can't
# answer "how many endpoints did each principal get past auth on" directly;
# this replays every declared operation once per principal instead, path
# params substituted the same way scan-nuclei.sh does.
#
# Filtered to the /api/v1/ prefix deliberately: the spec also lists
# auth-machinery endpoints (/auth/login, /auth/password-reset, /system/init,
# /auth/setup/*) that are UNAUTHENTICATED BY DESIGN and reject an empty/
# garbage body with their own 401 "invalid credentials" regardless of any
# Authorization header sent -- including those made every principal look
# identically ~0/167 non-401 (a first version of this script measured
# exactly that and it was wrong: a hand-verified GET /api/v1/users request
# with a real Bearer token returned 200, proving the auth mechanism itself
# was fine -- the confound was testing endpoints that 401 for reasons
# unrelated to the auth gate). Restricting to /api/v1/* and dropping the
# request body avoids that class of endpoint entirely.
#
# A second, more informative cut: 401 vs 403 vs 2xx per principal. 401 is
# "not authenticated", 403 is "authenticated but not permitted" -- viewer
# and admin are expected to look identical on the 401 count (both are valid
# sessions) and differ on 403 (least-privilege enforcement). Never write a
# token to this file -- only status codes.
OPS_FILE="$WORKDIR/results/.ops-list-$TIMESTAMP.txt"
curl -s http://localhost:8080/openapi.yaml | awk '
/^  \/[^ ]+:$/ { path=$0; sub(/^  /,"",path); sub(/:$/,"",path); next }
/^    (get|post|put|patch|delete|head|options):$/ {
    method=$0; sub(/^    /,"",method); sub(/:$/,"",method);
    print toupper(method), path
}
' | sed 's/{[^}]*}/00000000-0000-0000-0000-000000000000/g' | grep ' /api/v1/' > "$OPS_FILE"

COVERAGE_OUT="$WORKDIR/results/auth-coverage-$TIMESTAMP-$SCAN_SHA.txt"
if [ ! -s "$OPS_FILE" ]; then
    echo "[$(date -u +%FT%TZ)] could not parse any /api/v1/* operations from openapi.yaml, skipping coverage comparison" | tee "$COVERAGE_OUT"
else
    total=0
    anon_non401=0; user_non401=0; admin_non401=0
    user_2xx=0; user_403=0; admin_2xx=0; admin_403=0
    {
        echo "# auth coverage comparison, sha=$SCAN_SHA, generated $(date -u +%FT%TZ)"
        echo "# method  path  anon_status  user_status  admin_status"
        while read -r method path; do
            [ -z "$method" ] && continue
            total=$((total + 1))
            url="http://localhost:8080${path}"
            anon_code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url" || echo 000)
            user_code=$(dast_curl_bearer "$USER_TOKEN" -s -o /dev/null -w '%{http_code}' -X "$method" "$url" || echo 000)
            admin_code=$(dast_curl_bearer "$ADMIN_TOKEN" -s -o /dev/null -w '%{http_code}' -X "$method" "$url" || echo 000)
            [ "$anon_code" != "401" ] && anon_non401=$((anon_non401 + 1))
            [ "$user_code" != "401" ] && user_non401=$((user_non401 + 1))
            [ "$admin_code" != "401" ] && admin_non401=$((admin_non401 + 1))
            case "$user_code" in 2??) user_2xx=$((user_2xx + 1));; 403) user_403=$((user_403 + 1));; esac
            case "$admin_code" in 2??) admin_2xx=$((admin_2xx + 1));; 403) admin_403=$((admin_403 + 1));; esac
            echo "$method  $path  $anon_code  $user_code  $admin_code"
        done < "$OPS_FILE"
        echo "# TOTAL=$total anon_non401=$anon_non401 user_non401=$user_non401 admin_non401=$admin_non401"
        echo "# viewer: 2xx=$user_2xx 403=$user_403 | admin: 2xx=$admin_2xx 403=$admin_403"
    } > "$COVERAGE_OUT"
    echo "[$(date -u +%FT%TZ)] auth coverage ($total /api/v1/* operations): anon non-401=$anon_non401, viewer non-401=$user_non401 (2xx=$user_2xx 403=$user_403), admin non-401=$admin_non401 (2xx=$admin_2xx 403=$admin_403) -> $COVERAGE_OUT"
fi
rm -f "$OPS_FILE"

unset ADMIN_TOKEN USER_TOKEN
