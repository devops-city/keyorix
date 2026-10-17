#!/usr/bin/env bash
# scripts/drills/backup-restore.sh -- backup/restore drill (PROD-OPS-1 item 2).
#
# Source instance: provisioned, seeded (see lib.sh seed_data), run long enough for a
# signed audit checkpoint to exist, stopped; the checkpoint and its verification key
# are exported to a directory standing in for write-once media OFF the host; then
# `admin backup`. After the backup the source is started again and takes one more
# write, so the drill can show what the documented recovery point actually is.
#
# Target instance: a FRESH config + empty data directory (SQLite) or EMPTY database
# (PostgreSQL, DRILL_PG_DSN_FILE2), `admin restore --input <archive>`, then:
#   - restore's own verify-audit passed (its output says so);
#   - `admin verify-audit --anchor <external checkpoint> --checkpoint-key-file <key>`
#     reports VALID with the anchor authenticated;
#   - the server boots on the restored data; MFA login, every secret decrypts to the
#     seeded value, versions, share, machine token all work;
#   - the write made AFTER the backup is absent (recovery point = the backup).
# Negative legs: a one-byte-flipped archive is refused; restoring into a non-empty
# target is refused; restoring the old backup onto the host that has since moved on
# is refused without --allow-rollback.
#
# Usage:
#   [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt DRILL_PG_DSN_FILE2=b.txt] \
#   [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] scripts/drills/backup-restore.sh
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

drill_begin backup-restore
SRC=src
DST=dst
PSRC="$(drill_port 11)"
PDST="$(drill_port 12)"
EXT="$DRILL_DIR/external-media"
mkdir -p "$EXT"

# fresh_target <name> <port> [dsnfile]: config + certs + secrets copied from the source,
# NO keys and NO database -- what an operator has on a replacement host.
fresh_target() {
    local port="$2" dsnfile="${3:-}" d="$DRILL_DIR/$1"
    mkdir -p "$d/home"
    cp "$DRILL_DIR/$SRC/keyorix.yaml" "$d/keyorix.yaml"
    cp -R "$DRILL_DIR/$SRC/certs" "$d/certs"
    cp -R "$DRILL_DIR/$SRC/secrets" "$d/secrets"
    sed -i.bak -E "s/port: \"$PSRC\"/port: \"$port\"/" "$d/keyorix.yaml"
    if [ "$DRILL_BACKEND" = "postgres" ]; then
        pg_parse "$dsnfile"
        sed -i.bak -E "s/name: \"$SRC_PG_DB\"/name: \"$PG_DB\"/" "$d/keyorix.yaml"
    fi
    rm -f "$d/keyorix.yaml.bak"
}

# ---- source -----------------------------------------------------------------
inst_new "$SRC" "$PSRC"
SRC_PG_DB="${PG_DB:-}"
# a short checkpoint schedule so a signed checkpoint exists to export
printf '\naudit_checkpoints:\n  schedule: "3s"\n' >>"$DRILL_DIR/$SRC/keyorix.yaml"
srv_start "$SRC" "$PSRC"
seed_data "$SRC" "$PSRC"
step "wait out an audit-checkpoint interval"
sleep 8
if [ "$DRILL_BACKEND" = "postgres" ]; then
    step "LIVE backup beside the running server (PostgreSQL REPEATABLE READ snapshot)"
    inst_admin "$SRC" backup --output ./live.tar.gz >"$DRILL_DIR/backup-live.log" 2>&1 \
        || { cat "$DRILL_DIR/backup-live.log" >&2; fail "live admin backup on PostgreSQL failed"; }
    ok "live backup taken beside a running server"
else
    step "backup beside a LIVE SQLite server must be refused"
    if inst_admin "$SRC" backup --output ./refused.tar.gz >"$DRILL_DIR/backup-live.log" 2>&1; then
        fail "admin backup succeeded beside a live SQLite server (documented: refused)"
    fi
    [ ! -e "$DRILL_DIR/$SRC/refused.tar.gz" ] || fail "refused backup left an archive behind"
    ok "refused, no archive left behind"
fi
srv_stop "$SRC"

step "export the checkpoint anchor and its key to off-host media"
inst_admin "$SRC" audit export-checkpoint --output ./checkpoint-export.json >/dev/null \
    || fail "audit export-checkpoint failed"
inst_admin "$SRC" audit export-checkpoint-key --output ./checkpoint.key >/dev/null \
    || fail "audit export-checkpoint-key failed"
cp "$DRILL_DIR/$SRC/checkpoint-export.json" "$DRILL_DIR/$SRC/checkpoint.key" "$EXT/"
[ -s "$EXT/checkpoint-export.json" ] && [ -s "$EXT/checkpoint.key" ] || fail "exported anchor/key is empty"

step "admin backup (server stopped)"
inst_admin "$SRC" backup --output ./backup.tar.gz >"$DRILL_DIR/backup.log" 2>&1 \
    || { cat "$DRILL_DIR/backup.log" >&2; fail "admin backup failed"; }
cp "$DRILL_DIR/$SRC/backup.tar.gz" "$EXT/backup.tar.gz"
ok "archive $(wc -c <"$EXT/backup.tar.gz" | tr -d ' ') bytes"
# the archive carries the chain up to and including its own admin.backup_created event
verify_audit "$SRC"
AUDIT_AT_BACKUP="$AUDIT_COUNT"
step "backup refuses to overwrite an existing archive"
if inst_admin "$SRC" backup --output ./backup.tar.gz >/dev/null 2>&1; then
    fail "admin backup overwrote an existing archive"
fi
ok "refused"

step "the source moves on AFTER the backup (this write must NOT be in the restore)"
srv_start "$SRC" "$PSRC"
login_admin "$SRC" "$PSRC"
(umask 077 && printf 'after-backup-%s' "$(rand_hex 6)" >"$DRILL_DIR/$SRC/val.after")
cli "$SRC" "$PSRC" secret create --name after-backup --from-file ./val.after --project 1 --environment 1 >/dev/null \
    || fail "post-backup secret create failed"
srv_stop "$SRC"

# ---- negative legs ---------------------------------------------------------
step "negative: a tampered archive is refused"
python3 -I - "$EXT/backup.tar.gz" "$DRILL_DIR/tampered.tar.gz" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[len(data) // 2] ^= 0xFF
open(sys.argv[2], "wb").write(data)
PY
if [ "$DRILL_BACKEND" = "postgres" ]; then
    [ -n "${DRILL_PG_DSN_FILE3:-}" ] || echo "    (set DRILL_PG_DSN_FILE3 to also run the tamper leg on PostgreSQL; skipped)"
fi
if [ "$DRILL_BACKEND" = "sqlite" ] || [ -n "${DRILL_PG_DSN_FILE3:-}" ]; then
    fresh_target neg "$(drill_port 13)" "${DRILL_PG_DSN_FILE3:-}"
    if inst_admin neg restore --input "$DRILL_DIR/tampered.tar.gz" >"$DRILL_DIR/neg-tamper.log" 2>&1; then
        fail "admin restore accepted a tampered archive"
    fi
    ok "tampered archive refused: $(tail -1 "$DRILL_DIR/neg-tamper.log" | cut -c1-120)"
fi

step "negative: restoring this old backup onto the host that has moved on is refused"
if inst_admin "$SRC" restore --input "$EXT/backup.tar.gz" --overwrite-existing >"$DRILL_DIR/neg-rollback.log" 2>&1; then
    fail "restore of a stale backup over a newer database succeeded without --allow-rollback"
fi
grep -qiE 'rollback|behind|high-water' "$DRILL_DIR/neg-rollback.log" \
    || { cat "$DRILL_DIR/neg-rollback.log" >&2; fail "stale-backup refusal did not explain itself"; }
ok "refused with an explanation"

# ---- restore into a fresh target ------------------------------------------------
step "admin restore into a FRESH target"
fresh_target "$DST" "$PDST" "${DRILL_PG_DSN_FILE2:-}"
[ "$DRILL_BACKEND" = "sqlite" ] || [ -n "${DRILL_PG_DSN_FILE2:-}" ] || fail "postgres needs DRILL_PG_DSN_FILE2 (a second EMPTY database)"
inst_admin "$DST" restore --input "$EXT/backup.tar.gz" >"$DRILL_DIR/restore.log" 2>&1 \
    || { cat "$DRILL_DIR/restore.log" >&2; fail "admin restore failed"; }
grep -q 'VALID' "$DRILL_DIR/restore.log" || { cat "$DRILL_DIR/restore.log" >&2; fail "restore output does not show verify-audit VALID"; }
ok "restore finished; its own verify-audit said VALID"

step "restore into the now non-empty target is refused without --overwrite-existing"
if inst_admin "$DST" restore --input "$EXT/backup.tar.gz" >/dev/null 2>&1; then
    fail "second restore over a populated target succeeded without --overwrite-existing"
fi
ok "refused"

step "verify-audit against the restored database with the off-host anchor + key"
cp "$EXT/checkpoint-export.json" "$EXT/checkpoint.key" "$DRILL_DIR/$DST/"
out="$(inst_admin "$DST" verify-audit --json --anchor ./checkpoint-export.json --checkpoint-key-file ./checkpoint.key 2>&1)" \
    || { echo "$out" >&2; fail "verify-audit with anchor failed on the restored database"; }
echo "$out" | jq -e '.verdict == "VALID"' >/dev/null || { echo "$out" >&2; fail "verdict is not VALID"; }
echo "$out" | jq -e '.external_anchor.authenticated == true' >/dev/null || { echo "$out" >&2; fail "anchor not authenticated"; }
ok "VALID, anchor authenticated"

verify_audit "$DST"
[ "$AUDIT_COUNT" = "$AUDIT_AT_BACKUP" ] \
    || fail "restored audit chain has $AUDIT_COUNT events, the source had $AUDIT_AT_BACKUP at backup time"
ok "restored chain has exactly the $AUDIT_AT_BACKUP events the source had at backup time"

step "boot the restored instance and verify the data"
srv_start "$DST" "$PDST"
export DRILL_SEED_DIR="$SRC" DRILL_MFA_FROM="$SRC"
verify_seed "$DST" "$PDST"
if cli "$DST" "$PDST" secret get --id 4 --show-value >/dev/null 2>&1; then
    fail "the post-backup secret exists in the restore (recovery point is later than the backup?)"
fi
ok "post-backup write is absent: the recovery point is the backup, not the moment of the disaster"
srv_stop "$DST"
verify_audit "$DST"

drill_end "BACKUP/RESTORE DRILL"
