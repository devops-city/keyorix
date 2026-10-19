#!/usr/bin/env bash
# scripts/demo/scenario-dynamic-credentials.sh — catalogue scenario 6: dynamic database
# credentials.
#
# Keyorix creates a real, short-lived PostgreSQL role on demand (a "lease"), the application
# connects with it, the role disappears by itself when the TTL ends, and a second lease is
# revoked by hand on the spot (incident kill switch). Nothing long-lived is ever handed out.
#
# Needs a PostgreSQL the server may reach and a superuser-ish DSN for it. With a Postgres demo
# (native-up.sh with KEYORIX_DEMO_PG_DSN) that is the demo's own database; with a SQLite demo
# give any other database, e.g. one from `kpg dsn <name>`:
#
#   KEYORIX_DEMO_DYNAMIC_ADMIN_DSN='postgres://...' scripts/demo/scenario-dynamic-credentials.sh
#
# The DSN is read from the environment only. The demo server config native-up.sh writes enables
# the lease sweeper (10 s) and allows a database on this machine as the target.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init

ADMIN_DSN="${KEYORIX_DEMO_DYNAMIC_ADMIN_DSN:-${DEMO_PG_DSN:-}}"
[ -n "$ADMIN_DSN" ] || { echo "set KEYORIX_DEMO_DYNAMIC_ADMIN_DSN to a PostgreSQL DSN (e.g. from: kpg dsn demo_dyn) - a SQLite demo has no database of its own to hand out roles in" >&2; exit 2; }
DBEXEC="$SCN_REPO_ROOT/bin/demo-dbexec"
[ -x "$DBEXEC" ] || { echo "bin/demo-dbexec missing: go build -o bin/demo-dbexec ./scripts/demo/dbexec" >&2; exit 1; }
TTL=30
CFG_NAME="app-db"

# lease_dsn USER PASS -> a DSN for the same host/db as the admin DSN, logging in as USER.
lease_dsn() {
  KX_ADMIN="$ADMIN_DSN" KX_U="$1" KX_P="$2" python3 -I -c '
import os, urllib.parse as u
p = u.urlsplit(os.environ["KX_ADMIN"])
netloc = "%s:%s@%s" % (u.quote(os.environ["KX_U"]), u.quote(os.environ["KX_P"]), p.hostname + (":%d" % p.port if p.port else ""))
print(u.urlunsplit((p.scheme, netloc, p.path, p.query, "")))'
}

# who_am_i DSN -> prints the login role, or "DENIED" when the database refuses the connection.
who_am_i() {
  KEYORIX_DEMO_PG_DSN="$1" "$DBEXEC" query 'SELECT current_user' 2>/dev/null | head -n 1 || true
}

issue() { # prints: LEASE USER PASS
  local out
  out="$(scn_cli_as admin dynamic-secret issue "$CFG_ID" --ttl "$TTL")"
  printf '%s %s %s\n' \
    "$(printf '%s\n' "$out" | awk '$1 == "lease:" {print $2}')" \
    "$(printf '%s\n' "$out" | awk '$1 == "username:" {print $2}')" \
    "$(printf '%s\n' "$out" | awk '$1 == "password:" {print $2}')"
}

scn_step "1/5 register the database as a dynamic-secret target (admin DSN is encrypted at rest, never returned)"
CFG_ID="$(scn_cli_as admin dynamic-secret list --project-id 1 | awk -v n="$CFG_NAME" '$2 == n {print $1; exit}')"
if [ -z "$CFG_ID" ]; then
  KEYORIX_DYNAMIC_ADMIN_DSN="$ADMIN_DSN" scn_cli_as admin dynamic-secret create --name "$CFG_NAME" --project-id 1 \
    --backend postgres --default-ttl "$TTL" --max-ttl 300 \
    --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};' >/dev/null
  CFG_ID="$(scn_cli_as admin dynamic-secret list --project-id 1 | awk -v n="$CFG_NAME" '$2 == n {print $1; exit}')"
fi
[ -n "$CFG_ID" ] || { scn_fail "could not find or create the dynamic-secret config"; exit 1; }
scn_ok "config #$CFG_ID ($CFG_NAME, postgres, default TTL ${TTL}s, max 5 min)"

scn_step "2/5 lease: the app asks for a credential and gets a brand-new database role"
read -r LEASE1 DBUSER1 DBPASS1 <<EOT
$(issue)
EOT
[ -n "$LEASE1" ] && [ -n "$DBUSER1" ] && [ -n "$DBPASS1" ] || { scn_fail "issue returned no credential"; exit 1; }
scn_info "role: $DBUSER1   (password shown once by the CLI, never stored by Keyorix in the clear)   expires in ${TTL}s"
got="$(who_am_i "$(lease_dsn "$DBUSER1" "$DBPASS1")")"
[ "$got" = "$DBUSER1" ] || { scn_fail "could not log in to the database as the leased role (got '$got')"; exit 1; }
scn_ok "the database accepts the leased role: current_user = $got"

scn_step "3/5 TTL expiry: nobody revokes anything - waiting ~$((TTL + 20)) s"
end=$((SECONDS + TTL + 30))
got="$DBUSER1"
while [ "$SECONDS" -lt "$end" ]; do
  sleep 3
  got="$(who_am_i "$(lease_dsn "$DBUSER1" "$DBPASS1")")"
  [ -z "$got" ] && break
done
[ -z "$got" ] || { scn_fail "the leased role still works after its TTL (got '$got')"; exit 1; }
scn_ok "after the TTL the database refuses that role: the credential is gone by itself"

scn_step "4/5 revoke on demand: a second lease, used, then killed"
read -r LEASE2 DBUSER2 DBPASS2 <<EOT
$(issue)
EOT
got="$(who_am_i "$(lease_dsn "$DBUSER2" "$DBPASS2")")"
[ "$got" = "$DBUSER2" ] || { scn_fail "second lease did not work (got '$got')"; exit 1; }
scn_ok "second lease works: $got"
scn_cli_as admin dynamic-secret revoke "$LEASE2"
got="$(who_am_i "$(lease_dsn "$DBUSER2" "$DBPASS2")")"
[ -z "$got" ] || { scn_fail "the revoked role still works (got '$got')"; exit 1; }
scn_ok "revoked: the role was dropped immediately"

scn_step "5/5 the lease ledger and audit trail"
scn_cli_as admin dynamic-secret leases "$CFG_ID" | head -n 6
scn_cli_as admin audit logs --limit 12 | grep -iE 'dynamic|lease' | head -n 5 || true
scn_info "incident kill switch for everything at once: keyorix dynamic-secret revoke-all $CFG_ID"
