#!/usr/bin/env bash
# scripts/migrate/sqlite-to-pg-check.sh -- verify the Standalone -> Server growth path
# (SQLite -> PostgreSQL) end to end with real binaries (MIGRATE-VERIFY-1).
#
# The supported path is `keyorix-server admin backup` on the SQLite instance and
# `keyorix-server admin restore` into a config that points at an EMPTY PostgreSQL
# database (docs/SELF_HOSTING.md "Moving from SQLite to Postgres"). There is no
# separate migration tool. This script drives exactly that, then proves the result:
#
#   1. seed a realistic SQLite instance: projects, secrets with several versions, a
#      soft-deleted and a suspended secret, a share, two users with MFA, a group, a
#      machine identity with tokens, a dynamic-secret config, break-glass history,
#      >= 10k audit events and a retention-purge anchor, signed audit checkpoints;
#   2. stop it, `admin backup`, `admin restore` into PostgreSQL;
#   3. compare every table (row count + checksum) between the SQLite source and the
#      PostgreSQL target; the only rows allowed to differ are the audit events the
#      backup and the restore themselves append (checked by name);
#   4. boot the server on PostgreSQL: the MFA admin logs in, every secret decrypts
#      with the same keys, the machine token and the share work, suspended and
#      deleted secrets behave as before, verify-audit is VALID (also against the
#      off-host checkpoint anchor taken before the move: no new genesis), the
#      retention anchor is byte-identical, the schema epoch is the binary's;
#   5. failure and rollback: `kill -9` an `admin restore` midway, show the state it
#      leaves, that a re-run is refused or resumes, that the documented cleanup lets
#      it restart cleanly, and that the SQLite source file is untouched by restore.
#
# Usage (needs a PostgreSQL the script may fill: two EMPTY databases, URLs in files so
# the password never travels on a command line):
#   MIGRATE_PG_DSN_FILE=a.txt MIGRATE_PG_DSN_FILE2=b.txt MIGRATE_PG_DSN_FILE3=c.txt \
#     [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] scripts/migrate/sqlite-to-pg-check.sh
#   A (target of the migration), B (target of the restart-after-kill leg), C (a
#   throwaway database a dynamic-secret config points at).
#   MIGRATE_AUDIT_EVENTS=10000   number of recent audit events to seed (>= 10000)
#   DRILL_KEEP=1                 keep the work area (see scripts/drills/lib.sh)
set -euo pipefail
# shellcheck source=../drills/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../drills/lib.sh"

: "${MIGRATE_PG_DSN_FILE:?set MIGRATE_PG_DSN_FILE to a file holding the URL of an EMPTY PostgreSQL database}"
: "${MIGRATE_PG_DSN_FILE2:?set MIGRATE_PG_DSN_FILE2 to a file holding the URL of a second EMPTY database}"
: "${MIGRATE_PG_DSN_FILE3:?set MIGRATE_PG_DSN_FILE3 to a file holding the URL of any PostgreSQL database (dynamic-secret target)}"
MIGRATE_AUDIT_EVENTS="${MIGRATE_AUDIT_EVENTS:-10000}"
OLD_AUDIT_EVENTS=2000

DRILL_BACKEND=sqlite
drill_begin migrate-sqlite-to-pg
SRC=src
DST=dst
PSRC="$(drill_port 21)"
PDST="$(drill_port 22)"
EXT="$DRILL_DIR/external-media"
mkdir -p "$EXT"
MC="$DRILL_DIR/bin/migratecheck"
(cd "$DRILL_REPO_ROOT" && GOWORK=off go build -o "$MC" scripts/migrate/migratecheck/main.go) \
    || fail "migratecheck build failed"

# totp_fresh <secret>: a code that differs from the last one consumed FOR THIS SECRET (anti-replay is
# per account, and the migrated database carries the last-used step, so a login on the target inside
# the 30 s step of the last login on the source is correctly refused). scripts/drills/lib.sh keeps one
# "last code" for the whole run, which is not enough with two accounts; this replaces it.
totp_fresh() {
    local secret="$1" f code last i
    f="$DRILL_DIR/.last-totp.$(printf '%s' "$secret" | shasum | cut -c1-12)"
    for i in $(seq 1 40); do
        code="$(totp "$secret")"
        last="$(cat "$f" 2>/dev/null || true)"
        if [ "$code" != "$last" ]; then
            printf '%s' "$code" >"$f"
            echo "$code"
            return 0
        fi
        sleep 1
    done
    fail "could not get a fresh TOTP code"
}

# on_sqlite / on_pg: the lib helpers pick the backend from DRILL_BACKEND.
on_sqlite() { DRILL_BACKEND=sqlite; }
on_pg() { # <dsn-file>
    DRILL_BACKEND=postgres
    pg_parse "$1"
}

# mc <name> <args...>: run migratecheck in an instance dir with its config.
mc() {
    local name="$1"; shift
    inst_run "$name" env KEYORIX_CONFIG_PATH=./keyorix.yaml "$MC" "$1" --config ./keyorix.yaml "${@:2}"
}

# pg_target <name> <port> <dsn-file>: a fresh target instance: the SOURCE's config,
# certs and secrets (what an operator copies to the new host), NO keys, pointed at an
# empty PostgreSQL database. Sets PG_* for that database.
pg_target() {
    local name="$1" port="$2" dsnfile="$3" d="$DRILL_DIR/$1"
    mkdir -p "$d/home"
    cp "$DRILL_DIR/$SRC/keyorix.yaml" "$d/keyorix.yaml"
    cp -R "$DRILL_DIR/$SRC/certs" "$d/certs"
    cp -R "$DRILL_DIR/$SRC/secrets" "$d/secrets"
    pg_parse "$dsnfile"
    sed -i.bak -E \
        -e "s/port: \"$PSRC\"/port: \"$port\"/" \
        -e 's/^  type: sqlite.*/  type: postgres/' \
        -e "s|^    path: \"keyorix.db\"|    host: \"$PG_HOST\"\n    port: \"$PG_PORT\"\n    name: \"$PG_DB\"\n    user: \"$PG_USER\"\n    ssl_mode: disable|" \
        "$d/keyorix.yaml"
    rm -f "$d/keyorix.yaml.bak"
    grep -q 'type: postgres' "$d/keyorix.yaml" || fail "pg_target: config edit did not take ($name)"
}

# ============================================================================
# 1. seed
# ============================================================================
step "SQLite source: init + migrate"
on_sqlite
inst_new "$SRC" "$PSRC"
cat >>"$DRILL_DIR/$SRC/keyorix.yaml" <<'YAML'

audit_checkpoints:
  schedule: "3s"
dynamic_secrets:
  insecure_allow_private_network_dynamic_secret_targets: true
break_glass:
  enabled: true
  emergency_role: "project_developer"
  default_ttl: "1h"
  max_ttl: "2h"
YAML

step "old audit history ($OLD_AUDIT_EVENTS events, 30 days old: the retention purge will remove them)"
mc "$SRC" seed-audit --count "$OLD_AUDIT_EVENTS" --age-days 30 --tag old --restamp-head 3 >/dev/null \
    || fail "seeding old audit events failed"

srv_start "$SRC" "$PSRC"
seed_data "$SRC" "$PSRC"

# carol_cli <args...>: the CLI as the second MFA user (own session directory), against
# the instance in CAROL_INST on port CAROL_PORT.
CAROL_PW="Second-Op3rator-Passw0rd!-$(rand_hex 6)"
CAROL_INST="$SRC"
CAROL_PORT="$PSRC"
carol_cli() {
    local d="$DRILL_DIR/$CAROL_INST"
    mkdir -p "$d/home-carol"
    (
        cd "$d"
        HOME="$d/home-carol" KEYORIX_CA_FILE="$d/certs/server.crt" KEYORIX_SERVER="https://127.0.0.1:$CAROL_PORT" \
            KEYORIX_PASSWORD="$CAROL_PW" "$DRILL_CLI_BIN" "$@"
    )
}

seed_extras() {
    local d="$DRILL_DIR/$SRC" out
    mkdir -p "$d/home-carol"

    step "second user with MFA (carol, project_viewer) + a group"
    KEYORIX_INITIAL_PASSWORD="$CAROL_PW" cli "$SRC" "$PSRC" user create --username carol --email carol@drill.local >/dev/null \
        || fail "user create carol"
    cli "$SRC" "$PSRC" rbac assign-role --user carol@drill.local --role project_viewer --project default >/dev/null \
        || fail "assign carol project_viewer"
    carol_cli login --server "https://127.0.0.1:$PSRC" --username carol >/dev/null || fail "carol first login"
    out="$(carol_cli mfa enroll)" || fail "carol mfa enroll"
    local csecret
    csecret="$(echo "$out" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
    [ -n "$csecret" ] || fail "no MFA secret for carol"
    (umask 077 && printf '%s' "$csecret" >"$d/mfa.carol.secret")
    KEYORIX_MFA_CODE="$(totp_fresh "$csecret")" carol_cli mfa activate >/dev/null || fail "carol mfa activate"
    KEYORIX_MFA_CODE="$(totp_fresh "$csecret")" carol_cli login --server "https://127.0.0.1:$PSRC" --username carol >/dev/null \
        || fail "carol MFA login"
    cli "$SRC" "$PSRC" group create --name platform-team --description "platform on-call" >/dev/null || fail "group create"
    cli "$SRC" "$PSRC" group add-member platform-team --user alice >/dev/null || fail "group add-member alice"
    cli "$SRC" "$PSRC" group add-member platform-team --user carol >/dev/null || fail "group add-member carol"
    cli "$SRC" "$PSRC" rbac assign-role-to-group --help >/dev/null 2>&1 || true
    ok "carol (password + TOTP), group platform-team with 2 members"

    step "more secrets: second project secret with 2 versions, a soft-deleted one, a suspended one"
    (umask 077 && printf 'pay-api-v1-%s' "$(rand_hex 6)" >"$d/val.4")
    cli "$SRC" "$PSRC" secret create --name pay-api-key --from-file ./val.4 --project 1 --environment 1 >/dev/null || fail "create pay-api-key"
    (umask 077 && printf 'pay-api-v2-%s' "$(rand_hex 6)" >"$d/val.4")
    cli "$SRC" "$PSRC" secret update --id 4 --from-file ./val.4 >/dev/null || fail "update pay-api-key"
    cp "$d/val.4" "$d/expect.secret4"
    (umask 077 && printf 'old-cert-%s' "$(rand_hex 6)" >"$d/val.5")
    cli "$SRC" "$PSRC" secret create --name pay-old-cert --from-file ./val.5 --project 1 --environment 1 >/dev/null || fail "create pay-old-cert"
    cli "$SRC" "$PSRC" secret delete --id 5 --force >/dev/null || fail "soft-delete secret 5"
    (umask 077 && printf 'compromised-%s' "$(rand_hex 6)" >"$d/val.6")
    cli "$SRC" "$PSRC" secret create --name pay-compromised --from-file ./val.6 --project 1 --environment 1 >/dev/null || fail "create pay-compromised"
    cli "$SRC" "$PSRC" secret suspend --id 6 --reason "migration drill" >/dev/null || fail "suspend secret 6"
    ok "secret 4 (2 versions), secret 5 (soft-deleted), secret 6 (suspended)"

    step "machine identity with two tokens, one revoked"
    out="$(cli "$SRC" "$PSRC" machine token issue drill-ci --name drill-token-2 --project default --expires-in-days 7)" \
        || fail "second machine token"
    write_bearer "$d/bearer.revoked.hdr" "$(echo "$out" | grep '^Token:' | awk '{print $2}')"
    out="$(cli "$SRC" "$PSRC" machine token list drill-ci --project default)" || fail "machine token list"
    echo "$out" | head -20
    cli "$SRC" "$PSRC" machine token revoke drill-ci 2 --project default --force >/dev/null || fail "machine token revoke"

    step "dynamic-secret config (admin DSN is encrypted at rest)"
    on_pg "$MIGRATE_PG_DSN_FILE3"
    local dyn_dsn
    dyn_dsn="$(cat "$MIGRATE_PG_DSN_FILE3")"
    on_sqlite
    KEYORIX_DYNAMIC_ADMIN_DSN="$dyn_dsn" cli "$SRC" "$PSRC" dynamic-secret create --name drill-pg --project-id 1 --backend postgres \
        --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};' --default-ttl 600 --max-ttl 3600 >/dev/null \
        || fail "dynamic-secret create"
    cli "$SRC" "$PSRC" dynamic-secret list --project-id 1

    step "break-glass history: carol activates, admin revokes; carol activates again"
    carol_cli break-glass activate --project-id 1 --justification "drill: page at 03:00" --ttl 1h >/dev/null \
        || fail "break-glass activate (1)"
    out="$(cli "$SRC" "$PSRC" break-glass list --project-id 1)" || fail "break-glass list"
    echo "$out" | head -10
    cli "$SRC" "$PSRC" break-glass revoke --project-id 1 --activation-id 1 >/dev/null || fail "break-glass revoke"
    carol_cli break-glass activate --project-id 1 --justification "drill: second incident" --ttl 2h >/dev/null \
        || fail "break-glass activate (2)"
}
seed_extras

step "retention purge through the API: the 30-day-old history goes, a signed re-anchor stays"
out="$(cli "$SRC" "$PSRC" pat create --name purge-job --expires 2099-01-01)" || fail "pat create"
PURGE_TOKEN="$(echo "$out" | grep -oE 'kx_[A-Za-z0-9_-]+' | head -1)"
[ -n "$PURGE_TOKEN" ] || { echo "$out" >&2; fail "no token in pat create output"; }
write_bearer "$DRILL_DIR/$SRC/bearer.pat.hdr" "$PURGE_TOKEN"
(umask 077 && printf '{"retention_days":7}' >"$DRILL_DIR/$SRC/purge.json")
code="$(curl -s -o "$DRILL_DIR/$SRC/purge.out" -w '%{http_code}' --cacert "$DRILL_DIR/$SRC/certs/server.crt" \
    -H @"$DRILL_DIR/$SRC/bearer.pat.hdr" -H 'Content-Type: application/json' -X POST -d @"$DRILL_DIR/$SRC/purge.json" \
    "https://127.0.0.1:$PSRC/api/v1/admin/jobs/purge-audit-logs")"
[ "$code" = "200" ] || { cat "$DRILL_DIR/$SRC/purge.out" >&2; fail "purge-audit-logs returned HTTP $code"; }
PURGED="$(jq -r '.data.deleted_count' "$DRILL_DIR/$SRC/purge.out")"
[ "$PURGED" -ge "$OLD_AUDIT_EVENTS" ] || fail "purge removed $PURGED events, expected >= $OLD_AUDIT_EVENTS"
ok "purge removed $PURGED events"
srv_stop "$SRC"

step "recent audit history ($MIGRATE_AUDIT_EVENTS events) appended through the store's chained write path"
mc "$SRC" seed-audit --count "$MIGRATE_AUDIT_EVENTS" --age-days 1 --tag recent >/dev/null || fail "seeding recent audit events"
step "run the server again so a signed checkpoint covers the new head"
srv_start "$SRC" "$PSRC"
sleep 8
srv_stop "$SRC"

step "export the checkpoint anchor and its key to off-host media (taken BEFORE the move)"
inst_admin "$SRC" audit export-checkpoint --output ./checkpoint-export.json >/dev/null || fail "audit export-checkpoint failed"
inst_admin "$SRC" audit export-checkpoint-key --output ./checkpoint.key >/dev/null || fail "audit export-checkpoint-key failed"
cp "$DRILL_DIR/$SRC/checkpoint-export.json" "$DRILL_DIR/$SRC/checkpoint.key" "$EXT/"

# A chain with a retention gap only verifies VALID when the checkpoint key authenticates
# the gap (without the key it is INDETERMINATE by design), so every verify-audit below
# carries --checkpoint-key-file.
verify_audit "$SRC" --checkpoint-key-file ./checkpoint.key
[ "${AUDIT_COUNT:-0}" -ge 10000 ] || fail "source has only ${AUDIT_COUNT:-0} chained audit events, want >= 10000"
SRC_RETENTION_ANCHOR="$(mc "$SRC" meta --key audit_retention_anchor)" || fail "the source has no audit_retention_anchor (purge did not re-anchor?)"
SRC_EPOCH="$(mc "$SRC" meta --key schema_epoch)" || fail "no schema_epoch in the source"
ok "source: ${AUDIT_COUNT} chained events after a purge of $PURGED, schema_epoch $SRC_EPOCH"

# ============================================================================
# 2. migrate: admin backup (SQLite) -> admin restore (PostgreSQL)
# ============================================================================
step "state to be migrated: per-table row counts + checksums of the SQLite source"
mc "$SRC" table-sums >"$DRILL_DIR/src.sums" || fail "table-sums on the source"
SRC_AUDIT_MAX="$(jq -r 'select(.table=="__audit_max_id") | .count' "$DRILL_DIR/src.sums")"
SRC_ROWS="$(jq -s 'map(select(.table!="__audit_max_id") | .count) | add' "$DRILL_DIR/src.sums")"
ok "source: $(jq -s 'map(select(.table!="__audit_max_id" and .count>0)) | length' "$DRILL_DIR/src.sums") non-empty tables, $SRC_ROWS rows, newest audit id $SRC_AUDIT_MAX"

step "admin backup of the SQLite source (server stopped)"
inst_admin "$SRC" backup --output ./backup.tar.gz >"$DRILL_DIR/backup.log" 2>&1 \
    || { cat "$DRILL_DIR/backup.log" >&2; fail "admin backup failed"; }
cp "$DRILL_DIR/$SRC/backup.tar.gz" "$EXT/backup.tar.gz"
ok "archive $(wc -c <"$EXT/backup.tar.gz" | tr -d ' ') bytes"
# the backup is the only step that writes to the SQLite source: it appends its own
# admin.backup_created audit event to the source chain (after the snapshot, so it is
# not in the archive)
[ "$(mc "$SRC" audit-tail --after "$SRC_AUDIT_MAX" | cut -f2)" = "admin.backup_created" ] \
    || fail "expected exactly one admin.backup_created event appended to the source by the backup"
ok "the backup appended exactly one admin.backup_created event to the SQLite source chain (not part of the archive)"
# the SQLite file as the migration leaves it (the backup is the last thing that touched it)
SRC_DB_SHA="$(shasum -a 256 "$DRILL_DIR/$SRC/keyorix.db" | awk '{print $1}')"

step "admin restore into an EMPTY PostgreSQL database (same command, only the config's database differs)"
pg_target "$DST" "$PDST" "$MIGRATE_PG_DSN_FILE"
on_pg "$MIGRATE_PG_DSN_FILE"
T0=$SECONDS
inst_admin "$DST" restore --input "$EXT/backup.tar.gz" >"$DRILL_DIR/restore.log" 2>&1 \
    || { cat "$DRILL_DIR/restore.log" >&2; fail "admin restore into PostgreSQL failed"; }
ok "restore took $((SECONDS - T0))s"
grep -q 'VALID' "$DRILL_DIR/restore.log" || { cat "$DRILL_DIR/restore.log" >&2; fail "restore output does not show verify-audit VALID"; }
ok "restore's own verify-audit said VALID"
[ "$(shasum -a 256 "$DRILL_DIR/$SRC/keyorix.db" | awk '{print $1}')" = "$SRC_DB_SHA" ] \
    || fail "the SQLite source file changed during restore"
ok "the SQLite source file is byte-identical before and after the restore"

# ============================================================================
# 3. every row present and equal
# ============================================================================
# compare_to_source <inst>: every table of <inst> (PostgreSQL) equals the SQLite source's state
# at the moment before the backup. Audit events: only those up to the source's newest id (the
# target appends its own admin.restore_* events after them).
compare_to_source() {
    local inst="$1" mismatch
    mc "$inst" table-sums --audit-max-id "$SRC_AUDIT_MAX" >"$DRILL_DIR/$inst.sums" || fail "table-sums on $inst"
    mismatch="$(jq -n -r --slurpfile s "$DRILL_DIR/src.sums" --slurpfile d "$DRILL_DIR/$inst.sums" '
        ($s | map(select(.table != "__audit_max_id") | {(.table): .}) | add) as $S
      | ($d | map(select(.table != "__audit_max_id") | {(.table): .}) | add) as $D
      | $S | keys[]
      | select($S[.].count != ($D[.].count // -1) or $S[.].sha256 != ($D[.].sha256 // ""))
      | "\(.): sqlite \($S[.].count) rows \($S[.].sha256[0:12]), postgres \(($D[.].count // -1)) rows \(($D[.].sha256 // "")[0:12])"')"
    if [ -n "$mismatch" ]; then
        echo "$mismatch" >&2
        fail "tables differ between the SQLite source and the PostgreSQL target ($inst)"
    fi
}

step "per-table row counts + checksums: SQLite source vs PostgreSQL target"
compare_to_source "$DST"
ok "all $(jq -s 'map(select(.table!="__audit_max_id")) | length' "$DRILL_DIR/src.sums") tables equal (counts + checksums), $SRC_ROWS rows"
echo "    (not compared, by design: secret_nodes.cache_epoch, and system_metadata schema_epoch /"
echo "     schema_min_compatible_epoch / role_permissions_generation -- see scripts/migrate/migratecheck)"
TAIL="$(mc "$DST" audit-tail --after "$SRC_AUDIT_MAX")" || fail "audit-tail on the target"
echo "$TAIL" | cut -f2 | sort | uniq -c | sed 's/^/    audit events appended by the restore: /'
echo "$TAIL" | cut -f2 | grep -qx 'admin.restore_completed' || fail "no admin.restore_completed bridge event on the target"

step "audit chain: VALID, continuous, anchor-checked, retention anchor and schema epoch preserved"
cp "$EXT/checkpoint-export.json" "$EXT/checkpoint.key" "$DRILL_DIR/$DST/"
verify_audit "$DST" --checkpoint-key-file ./checkpoint.key
[ "$AUDIT_COUNT" -ge 10000 ] || fail "target chain has only $AUDIT_COUNT events"
out="$(inst_admin "$DST" verify-audit --json --anchor ./checkpoint-export.json --checkpoint-key-file ./checkpoint.key 2>&1)" \
    || { echo "$out" >&2; fail "verify-audit with the pre-migration anchor failed on PostgreSQL"; }
echo "$out" | jq -e '.verdict == "VALID" and .external_anchor.authenticated == true' >/dev/null \
    || { echo "$out" >&2; fail "PostgreSQL chain does not verify against the checkpoint exported from SQLite"; }
ok "VALID against the checkpoint exported from the SQLite instance before the move: no new genesis"
DST_RETENTION_ANCHOR="$(mc "$DST" meta --key audit_retention_anchor)" || fail "no audit_retention_anchor on the target"
[ "$DST_RETENTION_ANCHOR" = "$SRC_RETENTION_ANCHOR" ] || fail "retention anchor changed in the move"
ok "retention anchor byte-identical"
DST_EPOCH="$(mc "$DST" meta --key schema_epoch)"
BIN_EPOCH="$("$MC" epoch)"
[ "$DST_EPOCH" = "$SRC_EPOCH" ] && [ "$DST_EPOCH" = "$BIN_EPOCH" ] || fail "schema epoch: source $SRC_EPOCH, target $DST_EPOCH, binary $BIN_EPOCH"
ok "schema_epoch $DST_EPOCH on both sides and in the binary"

# ============================================================================
# 4. the migrated instance works: logins, MFA, decryption, tokens, states
# ============================================================================
step "boot the server on PostgreSQL with the migrated data"
srv_start "$DST" "$PDST"
export DRILL_SEED_DIR="$SRC" DRILL_MFA_FROM="$SRC"
verify_seed "$DST" "$PDST"
out="$(cli "$DST" "$PDST" secret get --id 4 --show-value)" || fail "secret 4 get"
echo "$out" | grep -qF "$(cat "$DRILL_DIR/$SRC/expect.secret4")" || fail "secret 4 does not decrypt to its latest version"
[ "$(cli "$DST" "$PDST" secret versions --id 4 | grep -cE '^[[:space:]]*[0-9]+[[:space:]]')" -ge 2 ] || fail "secret 4 lost a version"
ok "secret 4 decrypts, 2 versions"
if cli "$DST" "$PDST" secret get --id 6 --show-value >/dev/null 2>&1; then fail "suspended secret 6 is readable after the migration"; fi
ok "suspended secret 6 still refuses value reads"
if cli "$DST" "$PDST" secret get --id 5 --show-value >/dev/null 2>&1; then fail "soft-deleted secret 5 is readable after the migration"; fi
cli "$DST" "$PDST" secret trash --project 1 | grep -q 'pay-old-cert' || fail "soft-deleted secret 5 is not in the trash after the migration"
ok "soft-deleted secret 5 is unreadable and still in the trash"
[ "$(http_code "$DST" "$PDST" /api/v1/secrets/1 "$DRILL_DIR/$SRC/bearer.revoked.hdr")" = "401" ] \
    || fail "the REVOKED machine token still authenticates on PostgreSQL"
ok "revoked machine token still rejected (401); the live one works (verify_seed)"

CAROL_INST="$DST"
CAROL_PORT="$PDST"
KEYORIX_MFA_CODE="$(totp_fresh "$(cat "$DRILL_DIR/$SRC/mfa.carol.secret")")" carol_cli login --server "https://127.0.0.1:$PDST" --username carol >/dev/null \
    || fail "second user's password + TOTP login failed on PostgreSQL"
ok "second MFA user logs in with password + TOTP"
out="$(carol_cli break-glass list --project-id 1)" || fail "break-glass list as carol"
echo "$out" | grep -q 'drill: second incident' || fail "carol's break-glass history is gone"
out="$(cli "$DST" "$PDST" break-glass list --project-id 1)" || fail "break-glass list as admin"
[ "$(echo "$out" | grep -c 'drill:')" = "2" ] || { echo "$out" >&2; fail "break-glass history is not 2 activations"; }
ok "break-glass history: 2 activations (one revoked) visible to admin"
out="$(cli "$DST" "$PDST" group members platform-team)" || fail "group members"
if ! { echo "$out" | grep -q alice && echo "$out" | grep -q carol; }; then
    echo "$out" >&2
    fail "group membership lost"
fi
ok "group platform-team keeps both members"
cli "$DST" "$PDST" dynamic-secret list --project-id 1 | grep -q drill-pg || fail "dynamic-secret config lost"
out="$(cli "$DST" "$PDST" dynamic-secret issue 1 --ttl 60)" || { echo "$out" >&2; fail "dynamic-secret issue on the migrated config failed (admin DSN no longer decrypts?)"; }
ok "dynamic-secret config issues a credential (its encrypted admin DSN decrypts with the migrated keys)"
srv_stop "$DST"
verify_audit "$DST" --checkpoint-key-file ./checkpoint.key
ok "after the server ran on PostgreSQL the chain still verifies"

# ============================================================================
# 5. failure and rollback
# ============================================================================
# inst_bg <name> <logfile> <cmd...>: start a command in the instance dir in the background and
# leave its PID in BG_PID (exec, so the PID is the command's own, not a wrapper's).
inst_bg() {
    local name="$1" log="$2"; shift 2
    local d="$DRILL_DIR/$name"
    (
        cd "$d"
        # a per-subshell export is the intent
        # shellcheck disable=SC2031
        if [ "$DRILL_BACKEND" = "postgres" ]; then export KEYORIX_DB_PASSWORD="$PG_PASS"; fi
        exec env KEYORIX_CONFIG_PATH=./keyorix.yaml "$@"
    ) >"$log" 2>&1 &
    BG_PID=$!
}

# kill_restore_at <inst> <pattern>: start `admin restore` and kill -9 it as soon as its output shows
# <pattern>. Returns 1 if the restore ran to completion before the pattern appeared.
kill_restore_at() {
    local inst="$1" pattern="$2" log="$DRILL_DIR/kill-$1.log"
    inst_bg "$inst" "$log" "$DRILL_SERVER_BIN" admin restore --input "$EXT/backup.tar.gz" --config ./keyorix.yaml
    for _ in $(seq 1 4000); do
        grep -q "$pattern" "$log" 2>/dev/null && break
        kill -0 "$BG_PID" 2>/dev/null || break
        sleep 0.02
    done
    if kill -0 "$BG_PID" 2>/dev/null; then
        kill -9 "$BG_PID" 2>/dev/null || true
        wait "$BG_PID" 2>/dev/null || true
        return 0
    fi
    wait "$BG_PID" 2>/dev/null || true
    return 1
}

# restore_cleanup <inst>: the documented way to start a failed restore over -- remove the key files the
# interrupted restore installed and recreate the (empty) database. (docs/SELF_HOSTING.md)
restore_cleanup() {
    rm -f "$DRILL_DIR/$1/keys/dek.key" "$DRILL_DIR/$1/keys/kek.salt"
    mc "$1" reset-pg >/dev/null || fail "reset-pg on $1"
}

# failure_leg <label> <log pattern to kill at> <overwrite|cleanup>: kill -9 a restore into database B at
# that point, check what it left, that a plain re-run is refused, and that the chosen recovery works:
#   overwrite  re-run with --overwrite-existing (what the refusal message suggests)
#   cleanup    remove the key files it installed and recreate the empty database, then re-run
failure_leg() {
    local label="$1" pattern="$2" mode="$3" inst="kill-${1// /-}-$3" f
    step "kill -9 during restore: $label; recover by: $mode"
    pg_target "$inst" "$(drill_port 30)" "$MIGRATE_PG_DSN_FILE2"
    on_pg "$MIGRATE_PG_DSN_FILE2"
    kill_restore_at "$inst" "$pattern" || fail "the restore finished before it could be killed at '$pattern'"
    ok "restore killed (-9) after: $pattern"

    local keys rows ae
    keys=""
    for f in "$DRILL_DIR/$inst/keys"/*; do [ -e "$f" ] && keys="$keys$(basename "$f") "; done
    echo "    left behind: key files [${keys:-none}]"
    if rows="$(mc "$inst" table-sums 2>/dev/null)"; then
        ae="$(echo "$rows" | jq -r 'select(.table=="audit_events") | .count')"
        echo "    left behind: schema present, $(echo "$rows" | jq -s 'map(select(.table!="__audit_max_id")) | map(.count) | add') data rows, $ae audit events"
        [ "$ae" = "0" ] || fail "the load is not atomic: $ae audit events after a kill during the load"
    else
        echo "    left behind: no schema"
    fi
    [ "$(shasum -a 256 "$DRILL_DIR/$SRC/keyorix.db" | awk '{print $1}')" = "$SRC_DB_SHA" ] \
        || fail "the SQLite source changed while a restore was killed"
    ok "the SQLite source file is untouched"

    if inst_admin "$inst" restore --input "$EXT/backup.tar.gz" >"$DRILL_DIR/rerun-$inst.log" 2>&1; then
        fail "a restore over the leftovers of a killed restore was accepted without --overwrite-existing"
    fi
    echo "    plain re-run: refused: $(tail -1 "$DRILL_DIR/rerun-$inst.log" | cut -c1-150)..."
    case "$mode" in
        overwrite)
            inst_admin "$inst" restore --input "$EXT/backup.tar.gz" --overwrite-existing >"$DRILL_DIR/restart-$inst.log" 2>&1 \
                || { cat "$DRILL_DIR/restart-$inst.log" >&2; fail "restore --overwrite-existing over the leftovers of a killed restore failed"; }
            ;;
        cleanup)
            restore_cleanup "$inst"
            inst_admin "$inst" restore --input "$EXT/backup.tar.gz" >"$DRILL_DIR/restart-$inst.log" 2>&1 \
                || { cat "$DRILL_DIR/restart-$inst.log" >&2; fail "restore after the documented cleanup failed"; }
            ;;
    esac
    grep -q 'VALID' "$DRILL_DIR/restart-$inst.log" || fail "the restarted restore did not report verify-audit VALID"
    compare_to_source "$inst"
    ok "recovery ($mode): the restore runs clean, all tables equal the source"
    verify_audit "$inst" --checkpoint-key-file "$EXT/checkpoint.key"
    mc "$inst" reset-pg >/dev/null || true
}

failure_leg "while migrating the target" "Running migrations against the fresh target" overwrite
failure_leg "while migrating the target" "Running migrations against the fresh target" cleanup
failure_leg "while loading rows" "Loading data into the restored database" overwrite
failure_leg "while loading rows" "Loading data into the restored database" cleanup

step "rollback = do nothing to the SQLite source"
[ "$(shasum -a 256 "$DRILL_DIR/$SRC/keyorix.db" | awk '{print $1}')" = "$SRC_DB_SHA" ] || fail "SQLite source changed"
on_sqlite
srv_start "$SRC" "$PSRC"
login_admin "$SRC" "$PSRC"
ok "the SQLite source still starts and the admin still logs in (rolling back the migration = point the config back at it)"
srv_stop "$SRC"

drill_end "SQLITE -> POSTGRESQL MIGRATION CHECK"