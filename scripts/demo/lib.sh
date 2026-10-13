#!/usr/bin/env bash
# scripts/demo/lib.sh — helpers shared by scripts/demo/up.sh (SQLite) and
# scripts/demo/check.sh (--postgres seeds its own stack). Source it, don't run it.
#
# Why this exists: Keyorix ships with security.require_mfa ON (ADR-112), so a
# freshly bootstrapped admin is refused (HTTP 403 MFAEnrollmentRequired) on
# everything but MFA enrolment until it enrols TOTP. up.sh learnt that in #2982;
# check.sh's Postgres seed did not (#3034). Both now call demo_enroll_mfa
# and demo_login_mfa below instead of carrying their own copies.
#
# Everything goes through the public HTTP API (curl) with the secrets on stdin /
# in the process environment only, never as command-line arguments, so no
# "passing --password on the command line is insecure" warnings reach the
# presenter's terminal (#3034 finding 2). The TOTP codes come from
# scripts/totpgen (bin/totpgen), which stands in for an authenticator app.
#
# Contract for the caller: TOTPGEN_BIN must point at the built helper.
# Results are returned in DEMO_* globals (documented per function).

# shellcheck disable=SC2034  # DEMO_MFA_*/DEMO_RECOVERY_CODES/DEMO_TOKEN are read by the sourcing script
DEMO_HTTP_CODE=""
DEMO_BODY=""
DEMO_CODE=""

# demo_json '<python expr over d>' '<json>' — prints the value, '' on any error.
demo_json() {
  python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    v = $1
    print(v if v is not None else '')
except Exception:
    print('')
" "$2"
}

# demo_api METHOD BASE_URL PATH [TOKEN] [JSON_BODY]
# Sets DEMO_HTTP_CODE / DEMO_BODY. The JSON body is fed on stdin so credentials
# never appear in the curl command line.
demo_api() {
  local method="$1" base="$2" path="$3" token="${4:-}" body="${5:-}"
  local args=(-s --max-time 15 -X "$method" -w '\n%{http_code}' "${base}${path}")
  # The bearer token goes in a 0600 header file read via `-H @file`, never on argv.
  local hdr=""
  if [ -n "$token" ]; then
    hdr="$(mktemp)"
    ( umask 077; printf 'Authorization: Bearer %s\n' "$token" > "$hdr" )
    args+=(-H "@${hdr}")
  fi
  local out
  if [ -n "$body" ]; then
    out="$(printf '%s' "$body" | curl "${args[@]}" -H "Content-Type: application/json" --data-binary @-)"
  else
    out="$(curl "${args[@]}")"
  fi
  [ -n "$hdr" ] && rm -f "$hdr"
  DEMO_HTTP_CODE="${out##*$'\n'}"
  DEMO_BODY="${out%$'\n'*}"
}

# demo_totp_code SECRET — sets DEMO_CODE to a code for the next unused 30 s step. Every accepted
# code is single-use (anti-replay), so successive logins must each use a later
# step than the previous one; when the next free step is more than one step
# ahead of the clock (the server tolerates one), wait for the clock to catch up.
# Sets a global instead of printing: it must run in the caller's shell (not in
# $(...)) or the remembered step would be lost. The step is remembered per
# secret (the server's anti-replay counter is per account), in a variable named
# after it — no associative arrays, so this runs on macOS's bash 3.2 too — and
# mirrored to a file under DEMO_STEP_DIR so a LATER process (check.sh right after
# up.sh) knows which step up.sh already spent instead of guessing.
demo_totp_code() {
  local secret="$1" now step offset last_var last file_last step_file
  last_var="DEMO_LAST_TOTP_STEP_${secret}"
  last="${!last_var:-0}"
  step_file="${DEMO_STEP_DIR:-.demo-2-cli-home}/.totp-step-$(printf '%s' "$secret" | cksum | cut -d' ' -f1)"
  file_last="$(cat "$step_file" 2>/dev/null || echo 0)"
  case "$file_last" in ''|*[!0-9]*) file_last=0 ;; esac
  [ "$file_last" -gt "$last" ] && last="$file_last"
  now=$(date +%s)
  step=$((now / 30))
  [ "$step" -le "$last" ] && step=$((last + 1))
  if [ "$step" -gt $((now / 30 + 1)) ]; then
    sleep $(((step - 1) * 30 - now + 1))
    now=$(date +%s)
  fi
  offset=$(((step - now / 30) * 30))
  printf -v "$last_var" '%s' "$step"
  mkdir -p "$(dirname "$step_file")" 2>/dev/null && ( umask 077; printf '%s' "$step" > "$step_file" ) 2>/dev/null || true
  DEMO_CODE="$("$TOTPGEN_BIN" "$secret" "$offset")"
}

# demo_totp_last_step SECRET — prints the last 30 s step this tooling spent for the
# secret (0 if none), so a different process (the Playwright UI walk) can wait for
# a strictly later step instead of replaying a code the server already accepted.
demo_totp_last_step() {
  local secret="$1" last_var last file_last
  last_var="DEMO_LAST_TOTP_STEP_${secret}"
  last="${!last_var:-0}"
  file_last="$(cat "${DEMO_STEP_DIR:-.demo-2-cli-home}/.totp-step-$(printf '%s' "$secret" | cksum | cut -d' ' -f1)" 2>/dev/null || echo 0)"
  case "$file_last" in ''|*[!0-9]*) file_last=0 ;; esac
  [ "$file_last" -gt "$last" ] && last="$file_last"
  printf '%s' "$last"
}

# demo_login_mfa BASE_URL USER PASSWORD [TOTP_SECRET]
# Logs in over the API; if the account is challenged for a second factor, answers
# it with TOTP_SECRET. Sets DEMO_TOKEN (empty + non-zero return on failure, with
# the reason on stderr).
demo_login_mfa() {
  local base="$1" user="$2" password="$3" secret="${4:-}" challenge code
  DEMO_TOKEN=""
  demo_api POST "$base" /auth/login "" "$(DEMO_U="$user" DEMO_P="$password" python3 -c 'import json,os; print(json.dumps({"username":os.environ["DEMO_U"],"password":os.environ["DEMO_P"]}))')"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "login ($user) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  if [ "$(demo_json 'd["data"].get("mfa_required")' "$DEMO_BODY")" = "True" ]; then
    [ -n "$secret" ] || { echo "login ($user) needs a second factor but no TOTP secret is known" >&2; return 1; }
    challenge="$(demo_json 'd["data"]["mfa_challenge"]' "$DEMO_BODY")"
    demo_totp_code "$secret"
    demo_api POST "$base" /auth/mfa/verify "" "{\"mfa_challenge\":\"$challenge\",\"code\":\"$DEMO_CODE\"}"
    if [ "$DEMO_HTTP_CODE" = "401" ] && [ "${DEMO_LOGIN_RETRY:-0}" = "0" ]; then
      # Most likely this step's code was already spent by ANOTHER process (up.sh's
      # own final login, a minute ago) — this shell cannot know that. The step was
      # recorded as tried, so one fresh login picks the next step.
      DEMO_LOGIN_RETRY=1
      demo_login_mfa "$base" "$user" "$password" "$secret"
      local rc=$?
      DEMO_LOGIN_RETRY=0
      return $rc
    fi
    [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA verify ($user) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  fi
  DEMO_TOKEN="$(demo_json 'd["data"].get("token","")' "$DEMO_BODY")"
  [ -n "$DEMO_TOKEN" ] || { echo "login ($user) succeeded but returned no token: $DEMO_BODY" >&2; return 1; }
}

# demo_review_project BASE_URL TOKEN OTHER_TOKEN PROJECT_ID CAMPAIGN_NAME REASON
# Runs one complete access-review campaign (A.5.18 recertification) through the
# public API: open it (snapshots the project's current access), attest EVERY item
# with REASON, close it. No item is skipped and nothing is force-closed, so the
# resulting "reviewed" state is a real review of the seeded grants, not a
# bookkeeping shortcut. The product requires an INDEPENDENT reviewer (nobody
# attests their own access): TOKEN decides each item; where the server refuses
# that as "independent", the same item is decided by OTHER_TOKEN (the second
# administrator) instead. Any other refusal fails the run. Returns non-zero
# (reason on stderr) if any step is refused.
demo_review_project() {
  local base="$1" token="$2" other_token="$3" pid="$4" name="$5" reason="$6" cid item items body
  demo_api POST "$base" "/api/v1/projects/${pid}/access-review/campaigns" "$token" \
    "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1]}))' "$name")"
  [ "$DEMO_HTTP_CODE" = "200" ] || [ "$DEMO_HTTP_CODE" = "201" ] || { echo "open access-review campaign (project $pid) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  cid="$(demo_json 'd["data"]["campaign"]["id"]' "$DEMO_BODY")"
  [ -n "$cid" ] || { echo "open access-review campaign (project $pid) returned no campaign id: $DEMO_BODY" >&2; return 1; }
  demo_api GET "$base" "/api/v1/projects/${pid}/access-review/campaigns/${cid}" "$token"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "read access-review campaign $cid (project $pid) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  items="$(demo_json '" ".join(str(i["id"]) for i in d["data"].get("items") or [])' "$DEMO_BODY")"
  body="$(python3 -c 'import json,sys; print(json.dumps({"action":"attest","reason":sys.argv[1]}))' "$reason")"
  for item in $items; do
    demo_api POST "$base" "/api/v1/projects/${pid}/access-review/campaigns/${cid}/items/${item}/decide" "$token" "$body"
    if [ "$DEMO_HTTP_CODE" = "400" ] && printf '%s' "$DEMO_BODY" | grep -qi 'independent'; then
      demo_api POST "$base" "/api/v1/projects/${pid}/access-review/campaigns/${cid}/items/${item}/decide" "$other_token" "$body"
    fi
    [ "$DEMO_HTTP_CODE" = "200" ] || { echo "attest item $item of campaign $cid (project $pid) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  done
  demo_api POST "$base" "/api/v1/projects/${pid}/access-review/campaigns/${cid}/close" "$token" '{"force":false}'
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "close access-review campaign $cid (project $pid) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
}

# demo_enroll_mfa BASE_URL USER PASSWORD
# Enrols TOTP for a user that has none yet (a freshly bootstrapped admin, or any
# user, through the login session that is still allowed before MFA exists), then logs in again with a code. Sets
#   DEMO_MFA_SECRET, DEMO_MFA_URI, DEMO_RECOVERY_CODES (space-separated),
#   DEMO_TOKEN (a full, post-MFA session).
demo_enroll_mfa() {
  local base="$1" user="$2" password="$3" pre_token code
  DEMO_MFA_SECRET="" DEMO_MFA_URI="" DEMO_RECOVERY_CODES=""
  demo_login_mfa "$base" "$user" "$password" || return 1
  pre_token="$DEMO_TOKEN"

  demo_api POST "$base" /api/v1/auth/mfa/enroll "$pre_token" "{}"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA enroll returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  DEMO_MFA_SECRET="$(demo_json 'd["data"]["secret"]' "$DEMO_BODY")"
  DEMO_MFA_URI="$(demo_json 'd["data"]["otpauth_uri"]' "$DEMO_BODY")"
  [ -n "$DEMO_MFA_SECRET" ] && [ -n "$DEMO_MFA_URI" ] || { echo "MFA enroll returned no secret / otpauth URI" >&2; return 1; }

  demo_totp_code "$DEMO_MFA_SECRET"
  code="$DEMO_CODE"
  demo_api POST "$base" /api/v1/auth/mfa/activate "$pre_token" \
    "$(DEMO_C="$code" DEMO_P="$password" python3 -c 'import json,os; print(json.dumps({"code":os.environ["DEMO_C"],"password":os.environ["DEMO_P"]}))')"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA activate returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  DEMO_RECOVERY_CODES="$(demo_json '" ".join(d["data"].get("recovery_codes") or [])' "$DEMO_BODY")"

  # Activation signs the pre-MFA session out and consumed this 30 s step.
  demo_login_mfa "$base" "$user" "$password" "$DEMO_MFA_SECRET"
}

# demo_duration_seconds GO_DURATION — whole seconds of a Go duration ("2m45s",
# "10m41.18s", "1h0m0s"); '' when it does not parse.
demo_duration_seconds() {
  python3 -c "
import re, sys
m = re.fullmatch(r'(?:(\d+)h)?(?:(\d+)m)?(?:([0-9.]+)s)?', sys.argv[1])
if not m or not any(m.groups()):
    print('')
else:
    h, mi, s = m.groups()
    print(int(int(h or 0) * 3600 + int(mi or 0) * 60 + float(s or 0)))
" "$1"
}

# demo_uptime_seconds BASE_URL — how long the server process has been up (GET /health),
# '' when it cannot be read.
demo_uptime_seconds() {
  local d
  d="$(curl -s --max-time 5 "$1/health" | python3 -c 'import sys, json
try:
    print(json.load(sys.stdin).get("uptime", ""))
except Exception:
    print("")')"
  [ -n "$d" ] && demo_duration_seconds "$d"
}

# demo_open_anomalies BASE_URL TOKEN — prints one "ID TYPE SEVERITY ACCESSED_BY SECRET" line per
# UNACKNOWLEDGED anomaly alert, or the single line "ERROR <http code>" when the call fails
# (it usually runs inside $(...), so a global could not carry the status back).
demo_open_anomalies() {
  demo_api GET "$1" "/api/v1/audit/anomalies?unacknowledged=true" "$2"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "ERROR $DEMO_HTTP_CODE"; return 0; }
  python3 -c "
import sys, json
for a in json.loads(sys.argv[1])['data'].get('alerts') or []:
    print(a['ID'], a['AlertType'], a['Severity'], a.get('AccessedBy') or '-', a.get('SecretName') or '-')
" "$DEMO_BODY"
}

# demo_settle_anomalies BASE_URL ADMIN_TOKEN [CONTAINER]   (#3152)
#
# Anomaly detection runs in the background: its FIRST pass comes 1-5 minutes after the
# server starts, and it sees only what the seed script itself did (admin creating and
# classifying secrets, the one machine read, alice's one read). Every first access to a
# secret by a principal with no history is reported (low severity, "no prior baseline",
# internal/core/anomaly.go newIPAlert/newUserAlert) - correct detection, but it made a
# fresh demo grow a red "Alerts 13" tile a few minutes after the presenter opened it.
#
# So the script waits for that first pass and acknowledges exactly what the seed caused:
# a new_user / new_ip / off_hours alert of low or medium severity whose accessor is one of
# the seeded demo principals. Acknowledged alerts stay in the list (and in the audit
# trail); nothing is deleted and detection is untouched, so what the presenter does next
# (a login from a new place, a read by someone new) still raises a live alert. Anything
# else the first pass reports (high severity, a spike, an unknown accessor) is left open
# and check.sh fails on it.
#
# Best-effort: returns 0 even when it cannot settle (printing why), so a slow first pass
# never discards a good seed. CONTAINER (docker) lets it read the exact first-pass delay
# from the server log; without it the worst case (5 min) is waited.
demo_settle_anomalies() {
  local base="$1" token="$2" container="${3:-}" need=320 line d up wait tries=0 acked=0 left=0
  if [ -n "$container" ]; then
    line="$(docker logs "$container" 2>&1 | grep -m1 'Anomaly detection: first pass in' || true)"
    d="$(printf '%s' "$line" | sed -n 's/.*first pass in \([0-9hms.]*\),.*/\1/p')"
    [ -n "$d" ] && d="$(demo_duration_seconds "$d")"
    [ -n "$d" ] && need=$((d + 20))
  fi
  while :; do
    up="$(demo_uptime_seconds "$base")"
    [ -n "$up" ] || { echo "settle: could not read the server uptime; skipping" >&2; return 0; }
    [ "$up" -ge "$need" ] && break
    wait=$((need - up)); [ "$wait" -gt 10 ] && wait=10
    sleep "$wait"
  done
  # The pass may still be writing: look up to three times, 10 s apart, before concluding.
  local alerts=""
  while [ "$tries" -lt 3 ]; do
    alerts="$(demo_open_anomalies "$base" "$token")"
    [ -n "$alerts" ] && break
    tries=$((tries + 1)); sleep 10
  done
  local id type sev who secret
  while read -r id type sev who secret; do
    [ -n "$id" ] || continue
    case "$type:$sev:$who" in
      new_user:low:admin|new_user:low:alice|new_user:low:security-officer|new_user:low:ci-app|\
      new_ip:low:admin|new_ip:low:alice|new_ip:low:security-officer|new_ip:low:ci-app|\
      off_hours:medium:admin|off_hours:medium:alice|off_hours:medium:security-officer|off_hours:medium:ci-app)
        demo_api POST "$base" "/api/v1/audit/anomalies/$id/acknowledge" "$token" "{}"
        if [ "$DEMO_HTTP_CODE" = "200" ]; then acked=$((acked + 1)); else left=$((left + 1)); fi
        ;;
      *) left=$((left + 1)) ;;
    esac
  done <<EOT
$alerts
EOT
  echo "settle: acknowledged $acked first-observation alert(s) caused by the seed itself; $left left open"
  return 0
}

# demo_stamp_build_args sets DEMO_STAMP_ARGS to the docker build args that stamp the image
# with the real build identity (internal/version: Version, Commit, BuildDate), so /health,
# /system/info, `keyorix system info` and the web footer do not report dev/none/unknown.
# Same sources as the Makefile: the nearest tag, the short commit and the COMMIT date (never
# wall clock, so a rebuild of the same commit is reproducible). Outside a git checkout the
# Dockerfile defaults apply and the UI/CLI show the build as not stamped.
demo_stamp_build_args() {
  local root="${1:-$REPO_ROOT}" ver commit bdate
  DEMO_STAMP_ARGS=()
  ver="$(git -C "$root" describe --tags --always --dirty 2>/dev/null)" || return 0
  commit="$(git -C "$root" rev-parse --short HEAD 2>/dev/null)" || return 0
  bdate="$(TZ=UTC git -C "$root" log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" || return 0
  DEMO_STAMP_ARGS=(--build-arg "VERSION=$ver" --build-arg "GIT_COMMIT=$commit" --build-arg "BUILD_DATE=$bdate")
}
