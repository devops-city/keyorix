#!/usr/bin/env bash
# scripts/demo/scn-lib.sh — helpers shared by the demo scenario scripts
# (scripts/demo/trigger-anomaly.sh, scripts/demo/scenario-*.sh). Source it, don't run it.
#
# It finds the running demo through its state file (default: .demo-native/state.env,
# written by scripts/demo/native-up.sh; override with KEYORIX_DEMO_DIR) and gives the
# scenario scripts: a cached admin/alice/officer session (every login AND every MFA verify
# spends one of the 10-per-15-minute per-IP login attempts, so sessions are cached in the
# CLI home and reused while they are valid), a CLI wrapper, and anomaly-list helpers.
#
# Credentials never reach a command line: passwords and TOTP keys come from the 0600 state
# file, tokens travel in 0600 header files (`curl -H @file`) or the process environment.
# shellcheck disable=SC2034  # variables are read by the sourcing script

SCN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCN_REPO_ROOT="$(cd "$SCN_LIB_DIR/../.." && pwd)"
SCN_WORK="${KEYORIX_DEMO_DIR:-$SCN_REPO_ROOT/.demo-native}"

# shellcheck source=scripts/demo/lib.sh
. "$SCN_LIB_DIR/lib.sh"

scn_step() { printf '\033[0;36m==>\033[0m %s\n' "$1"; }
scn_info() { printf '\033[0;34m  i\033[0m %s\n' "$1"; }
scn_ok()   { printf '\033[0;32m  ok\033[0m %s\n' "$1"; }
scn_fail() { printf '\033[0;31m FAIL\033[0m %s\n' "$1" >&2; }

scn_init() {
  [ -f "$SCN_WORK/state.env" ] || { echo "no demo state at $SCN_WORK/state.env — run scripts/demo/native-up.sh first" >&2; return 1; }
  # shellcheck disable=SC1091
  . "$SCN_WORK/state.env"
  SCN_URL="$DEMO_URL"
  CLI_BIN="$SCN_REPO_ROOT/bin/keyorix"
  TOTPGEN_BIN="$SCN_REPO_ROOT/bin/totpgen"
  SCN_CLI_HOME="$SCN_WORK/cli-home"
  DEMO_STEP_DIR="$SCN_CLI_HOME"
  export HOME="$SCN_CLI_HOME"
  export KEYORIX_SERVER="$SCN_URL"
  [ -x "$CLI_BIN" ] && [ -x "$TOTPGEN_BIN" ] || { echo "bin/keyorix or bin/totpgen missing — run scripts/demo/native-up.sh" >&2; return 1; }
  curl -s -o /dev/null --max-time 3 "$SCN_URL/health" || { echo "demo server not reachable at $SCN_URL" >&2; return 1; }
}

# scn_token USER — sets SCN_TOKEN to a valid session for admin|alice|officer, logging in
# (password + TOTP) only when the cached one is gone or expired.
scn_token() {
  local who="$1" file="$SCN_CLI_HOME/.scn-token-$1" user pass totp
  if [ -s "$file" ]; then
    SCN_TOKEN="$(cat "$file")"
    demo_api GET "$SCN_URL" /api/v1/auth/profile "$SCN_TOKEN"
    [ "$DEMO_HTTP_CODE" = "200" ] && return 0
  fi
  case "$who" in
    admin)   user="admin";            pass="$DEMO_ADMIN_PASSWORD";   totp="$DEMO_ADMIN_TOTP" ;;
    alice)   user="alice";            pass="$DEMO_ALICE_PASSWORD";   totp="$DEMO_ALICE_TOTP" ;;
    officer) user="security-officer"; pass="$DEMO_OFFICER_PASSWORD"; totp="$DEMO_OFFICER_TOTP" ;;
    *) echo "scn_token: unknown user $who" >&2; return 1 ;;
  esac
  demo_login_mfa "$SCN_URL" "$user" "$pass" "$totp" || return 1
  SCN_TOKEN="$DEMO_TOKEN"
  ( umask 077; printf '%s' "$SCN_TOKEN" > "$file" )
}

# scn_cli_as USER ARGS... — run the keyorix CLI as admin|alice|officer.
scn_cli_as() {
  local who="$1"; shift
  scn_token "$who" || return 1
  KEYORIX_TOKEN="$SCN_TOKEN" "$CLI_BIN" "$@"
}

# scn_get_with_token TOKEN PATH [extra curl args...] — GET with the token in a header file.
# Prints "<http code>" on the last line, the body above it. TOKEN is any bearer (machine too).
scn_get_with_token() {
  local token="$1" path="$2" hdr out; shift 2
  hdr="$(mktemp)"
  ( umask 077; printf 'Authorization: Bearer %s\n' "$token" > "$hdr" )
  out="$(curl -s --max-time 15 -w '\n%{http_code}' -H "@$hdr" "$@" "${SCN_URL}${path}")"
  rm -f "$hdr"
  printf '%s\n' "$out"
}

# scn_http_code TOKEN PATH [curl args...] — just the HTTP status.
scn_http_code() {
  scn_get_with_token "$@" | tail -n 1
}

# scn_open_anomalies — one "ID TYPE SEVERITY ACCESSED_BY SECRET" line per UNACKNOWLEDGED alert.
scn_open_anomalies() {
  scn_token admin || return 1
  demo_open_anomalies "$SCN_URL" "$SCN_TOKEN"
}

# scn_open_count — number of unacknowledged anomaly alerts (prints ERROR... on failure).
scn_open_count() {
  local lines
  lines="$(scn_open_anomalies)"
  case "$lines" in ERROR*) echo "$lines"; return 1 ;; esac
  if [ -z "$lines" ]; then echo 0; else printf '%s\n' "$lines" | wc -l | tr -d ' '; fi
}

# scn_wait_anomaly TYPE [SECONDS] [WHO] — poll until an open alert of TYPE exists (default
# 90 s), optionally only for accessor WHO; prints the matching lines and returns 0, or
# returns 1 on timeout. Only alerts whose id is above SCN_ALERT_FLOOR count (set it with
# scn_mark_alerts before triggering, so an alert left over from earlier never satisfies it).
scn_wait_anomaly() {
  local type="$1" limit="${2:-90}" who="${3:-}" waited=0 lines hit
  while [ "$waited" -le "$limit" ]; do
    lines="$(scn_open_anomalies)"
    hit="$(printf '%s\n' "$lines" | awk -v t="$type" -v w="$who" -v f="${SCN_ALERT_FLOOR:-0}" '$2 == t && $1 > f && (w == "" || $4 == w)')"
    if [ -n "$hit" ]; then printf '%s\n' "$hit"; return 0; fi
    sleep 3; waited=$((waited + 3))
  done
  return 1
}

# scn_mark_alerts — remember the highest anomaly id that exists now (SCN_ALERT_FLOOR),
# including acknowledged ones, so later waits only accept alerts raised after this point.
scn_mark_alerts() {
  scn_token admin || return 1
  demo_api GET "$SCN_URL" "/api/v1/audit/anomalies" "$SCN_TOKEN"
  SCN_ALERT_FLOOR="$(demo_json 'max([a["ID"] for a in (d["data"].get("alerts") or [])] or [0])' "$DEMO_BODY")"
  SCN_ALERT_FLOOR="${SCN_ALERT_FLOOR:-0}"
}

# scn_ack_all — acknowledge every open anomaly alert; prints how many.
scn_ack_all() {
  local n=0 id rest
  scn_token admin || return 1
  while read -r id rest; do
    [ -n "$id" ] || continue
    case "$id" in ERROR) echo "cannot list anomalies: $rest" >&2; return 1 ;; esac
    demo_api POST "$SCN_URL" "/api/v1/audit/anomalies/$id/acknowledge" "$SCN_TOKEN" "{}"
    [ "$DEMO_HTTP_CODE" = "200" ] && n=$((n + 1))
  done <<EOT
$(demo_open_anomalies "$SCN_URL" "$SCN_TOKEN")
EOT
  echo "$n"
}

# scn_db MODE SQL [PARAM...] — run SQL straight against the demo's database (SQLite file or
# the PostgreSQL DSN in the state file), MODE = query (rows, tab-separated) or exec. Write
# parameters as $1, $2 ... (translated to ?1, ?2 for SQLite). Used only by scenarios that
# deliberately bypass the product (tamper-evident audit), never to seed or to "fake" a result.
scn_db() {
  local mode="$1" sql="$2"; shift 2
  if [ "${DEMO_STORAGE:-sqlite}" = "postgres" ]; then
    KEYORIX_DEMO_PG_DSN="$DEMO_PG_DSN" "$SCN_REPO_ROOT/bin/demo-dbexec" "$mode" "$sql" "$@"
  else
    python3 -I - "${DEMO_DB_FILE:-$SCN_WORK/keyorix.db}" "$mode" "$sql" "$@" <<'PY'
import re, sqlite3, sys
db, mode, sql, *params = sys.argv[1:]
c = sqlite3.connect(db, timeout=15)
sql = re.sub(r"\$(\d+)", r"?\1", sql)
cur = c.execute(sql, params)
if mode == "query":
    for row in cur.fetchall():
        print("\t".join("" if v is None else str(v) for v in row))
else:
    c.commit()
    print("%d row(s) affected" % cur.rowcount)
PY
  fi
}
