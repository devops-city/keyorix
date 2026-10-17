#!/usr/bin/env bash
# scripts/drills/upgrade.sh -- upgrade drill (PROD-OPS-1 item 1).
#
# Starts the OLD release (DRILL_OLD_SERVER_BIN, e.g. the newest
# tag built with `go build ./server`), seeds realistic data through the current CLI
# (projects, secrets with versions, a share, users, an MFA-enrolled admin, a machine
# identity and token, and the audit history all of that writes), stops it, swaps in
# the binary under test (DRILL_SERVER_BIN, default: this checkout) and checks:
#   - the new binary boots on the old data and says in its startup log what
#     docs/UPGRADING.md says it will say;
#   - every seeded secret still decrypts, versions, share, MFA login and machine
#     token all still work;
#   - `admin verify-audit` is VALID before and after the upgrade;
#   - the audit trail grew (the upgrade did not rewrite history).
#
# Usage:
#   DRILL_OLD_SERVER_BIN=/path/old/keyorix-server \
#   [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=/path/dsn.txt] scripts/drills/upgrade.sh
#
# Exit 0 = every check passed; the last line is "UPGRADE DRILL PASSED".
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

: "${DRILL_OLD_SERVER_BIN:?set DRILL_OLD_SERVER_BIN to the previous release keyorix-server binary}"
[ -x "$DRILL_OLD_SERVER_BIN" ] || fail "DRILL_OLD_SERVER_BIN is not executable"

drill_begin upgrade
NEW_SERVER_BIN="$DRILL_SERVER_BIN"
PORT="$(drill_port 1)"
INST=inst

old_ver="$("$DRILL_OLD_SERVER_BIN" --version 2>&1 | head -1)"
new_ver="$("$NEW_SERVER_BIN" --version 2>&1 | head -1)"
echo "==> old: $old_ver"
echo "==> new: $new_ver"

# ---- 1. old release: provision and seed ------------------------------------
DRILL_SERVER_BIN="$DRILL_OLD_SERVER_BIN"
inst_new "$INST" "$PORT"
srv_start "$INST" "$PORT" "$DRILL_OLD_SERVER_BIN"
seed_data "$INST" "$PORT"
step "verify the seed on the OLD release"
verify_seed "$INST" "$PORT"

# audit checkpoints and the append-only audit writer flush on stop
srv_stop "$INST"
export DRILL_ADMIN_BIN="$DRILL_OLD_SERVER_BIN"  # lib.sh inst_admin runs this binary
verify_audit "$INST"
audit_before="$AUDIT_COUNT"
unset DRILL_ADMIN_BIN

# ---- 2. swap the binary ----------------------------------------------------
step "dry checks with the NEW binary while the server is stopped"
DRILL_SERVER_BIN="$NEW_SERVER_BIN"
out="$(inst_admin "$INST" validate 2>&1)" || { echo "$out" >&2; fail "admin validate failed on the old data with the new binary"; }
ok "admin validate"

step "start the NEW binary on the OLD data"
: >"$DRILL_DIR/$INST/server.log"
srv_start "$INST" "$PORT" "$NEW_SERVER_BIN"
cp "$DRILL_DIR/$INST/server.log" "$DRILL_DIR/startup-after-upgrade.log"

step "startup log matches docs/UPGRADING.md"
log="$DRILL_DIR/startup-after-upgrade.log"
if grep -qiE 'panic|fatal|FAIL' "$log"; then
    grep -iE 'panic|fatal|FAIL' "$log" | head -5 >&2
    fail "startup log of the new binary contains an error line"
fi
# UPGRADING.md: a v0.95.x->v0.96 upgrade logs the ADR-112 grace line. From v0.96.x
# on the config already has require_mfa: true written by admin init, so no grace line.
if grep -q 'ADR-112 grace period' "$log"; then
    echo "    NOTE: ADR-112 grace period line present (expected only when upgrading a pre-v0.96 config)"
fi
ok "no error lines at startup (log: $log)"
# UPGRADING.md 6c: PostgreSQL logs the audit durability level at start; SQLite runs strict only.
if [ "$DRILL_BACKEND" = "postgres" ]; then
    grep -q 'INFO: audit durability: standard' "$log" || fail "UPGRADING.md 6c says a PostgreSQL start logs 'audit durability: standard'; the log has no such line"
    ok "log carries the 6c audit durability line"
fi

step "verify the seed on the NEW release"
verify_seed "$INST" "$PORT"

step "write after the upgrade"
(umask 077 && printf 'post-upgrade-%s' "$(rand_hex 6)" >"$DRILL_DIR/$INST/val.post")
cli "$INST" "$PORT" secret create --name post-upgrade --from-file ./val.post --project 1 --environment 1 >/dev/null \
    || fail "cannot write a secret after the upgrade"
out="$(cli "$INST" "$PORT" secret get --id 4 --show-value)"
echo "$out" | grep -qF "$(cat "$DRILL_DIR/$INST/val.post")" || fail "post-upgrade secret does not read back"
ok "post-upgrade write + read"

srv_stop "$INST"
step "verify-audit with the NEW binary"
verify_audit "$INST"
[ "${AUDIT_COUNT:-0}" -gt "${audit_before:-0}" ] 2>/dev/null \
    || fail "audit trail did not grow across the upgrade (before ${audit_before:-?}, after ${AUDIT_COUNT:-?})"
ok "audit trail grew: $audit_before -> $AUDIT_COUNT chained events"

# UPGRADING.md 7.4: once the database's schema epoch has advanced, the OLD binary must
# refuse to start on it ("database schema epoch N is newer than this binary's schema
# epoch M"). If the two versions share an epoch the old binary may legitimately start;
# either way it must not corrupt anything, so report which happened.
step "downgrade probe: the OLD binary on the migrated data"
: >"$DRILL_DIR/$INST/server.log"
if (srv_start "$INST" "$PORT" "$DRILL_OLD_SERVER_BIN") >"$DRILL_DIR/downgrade-probe.out" 2>&1; then
    srv_stop "$INST"
    echo "    NOTE: the old binary started on the migrated data (no schema-epoch advance between these versions)"
else
    rm -f "$DRILL_DIR/$INST/server.pid"
    if grep -q 'schema epoch' "$DRILL_DIR/$INST/server.log"; then
        ok "old binary refused the migrated database with the schema-epoch message"
    else
        tail -5 "$DRILL_DIR/$INST/server.log" >&2
        fail "old binary failed on the migrated data without the documented schema-epoch message"
    fi
fi

drill_end "UPGRADE DRILL"
