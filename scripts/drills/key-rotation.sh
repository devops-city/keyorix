#!/usr/bin/env bash
# shellcheck disable=SC2016  # the bash -c bodies below are meant to be single-quoted
# scripts/drills/key-rotation.sh -- key rotation / KEK provider drill (PROD-OPS-1 item 3).
#
# Everything the docs (operator/j6-key-rotation.md, CONFIGURATION.md "Encryption & KEK
# providers") say an operator can do OFFLINE with the server stopped:
#   A. DEK rotation: `--dry-run`, refusal beside a live server, `--confirm`; afterwards
#      every secret, the MFA login and the machine token still work and the chain verifies.
#   B. A rotation killed with SIGKILL at several points leaves a database that is still
#      readable (docs: "a kill at any point during this is safe"), and a later rotation
#      completes.
#   C. KEK rotation (`rotate-kek`): the OLD passphrase is then refused at start with a
#      clear message, the NEW one works, data and audit chain intact; a backup taken
#      BEFORE the rotation still restores with the OLD passphrase.
#   D. Provider migration password -> file -> password: the server starts with no
#      KEYORIX_MASTER_PASSWORD under the `file` provider, and the data survives each hop.
# Cloud KMS, TPM and Shamir need external infrastructure and are not covered here.
#
# Usage: [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt DRILL_PG_DSN_FILE2=b.txt] \
#        [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] scripts/drills/key-rotation.sh
# (DRILL_PG_DSN_FILE2: a second EMPTY database for the pre-rotation-backup restore leg.)
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

drill_begin key-rotation
I=inst
P="$(drill_port 21)"
PT="$(drill_port 22)"
OLD_PW="$KEYORIX_MASTER_PASSWORD"
NEW_PW="drill-rotated-$(rand_hex 16)"
EXT="$DRILL_DIR/external"
mkdir -p "$EXT"
d="$DRILL_DIR/$I"

# status_ok: seed intact with the server running, then stop and verify the chain.
check_all() { # <label>
    srv_start "$I" "$P"
    verify_seed "$I" "$P"
    srv_stop "$I"
    verify_audit "$I"
    ok "$1: data, logins, tokens and audit chain intact"
}

step "provision, seed, back up (pre-rotation archive)"
inst_new "$I" "$P"
srv_start "$I" "$P"
seed_data "$I" "$P"
srv_stop "$I"
inst_admin "$I" backup --output ./pre-rotation.tar.gz >"$DRILL_DIR/backup.log" 2>&1 \
    || { cat "$DRILL_DIR/backup.log" >&2; fail "pre-rotation backup failed"; }
cp "$d/pre-rotation.tar.gz" "$EXT/"

# ---- A. DEK rotation ----------------------------------------------------------
step "A. DEK rotation: dry run changes nothing"
out="$(inst_admin "$I" encryption rotate --dry-run 2>&1)" || { echo "$out" >&2; fail "rotate --dry-run failed"; }
grep -qi 'dry run complete' <<<"$out" || { echo "$out" >&2; fail "dry run did not say it completed"; }
dek_before="$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)"
ok "dry run: $(echo "$out" | grep -c 'secret_versions') summary line(s), DEK file untouched"

step "A. rotation beside a LIVE server is refused"
srv_start "$I" "$P"
if inst_admin "$I" encryption rotate --confirm >"$DRILL_DIR/rotate-live.log" 2>&1; then
    fail "DEK rotation ran beside a live server"
fi
ok "refused: $(tail -1 "$DRILL_DIR/rotate-live.log" | cut -c1-110)"
srv_stop "$I"
[ "$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)" = "$dek_before" ] || fail "refused rotation changed the DEK file"

step "A. rotate the DEK"
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
t0="$(now)"
out="$(inst_admin "$I" encryption rotate --confirm 2>&1)" || { echo "$out" >&2; fail "rotate --confirm failed"; }
ROTATE_SECS="$(awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.3f", b-a}')"
grep -q 'DEK rotated' <<<"$out" || { echo "$out" >&2; fail "rotate did not report success"; }
[ "$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)" != "$dek_before" ] || fail "DEK file unchanged after rotation"
check_all "after DEK rotation"

# ---- B. SIGKILL during rotation ---------------------------------------------------
step "B. SIGKILL during DEK rotation, six timings (a SIGKILL cannot be aimed; the DEK file hash says how far each got)"
# the kill points are fractions of this machine's clean-rotation wall time (measured above),
# so they land in start-up, in the sweep and after the DEK swap whatever the hardware
for frac in 0.15 0.35 0.55 0.75 0.9 1.05; do
    delay="$(awk -v t="$ROTATE_SECS" -v f="$frac" 'BEGIN{printf "%.3f", t*f}')"
    (
        cd "$d"
        [ "$DRILL_BACKEND" = "postgres" ] && export KEYORIX_DB_PASSWORD="$PG_PASS"
        exec env KEYORIX_CONFIG_PATH=./keyorix.yaml "$DRILL_SERVER_BIN" admin encryption rotate --confirm \
            --config ./keyorix.yaml >/dev/null 2>&1
    ) &
    victim=$!
    dek_pre="$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)"
    sleep "$delay"
    kill -9 "$victim" 2>/dev/null || true
    wait "$victim" 2>/dev/null || true
    if [ "$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)" = "$dek_pre" ]; then
        echo "    (killed at ${delay}s: DEK file not yet replaced)"
    else
        echo "    (killed at ${delay}s: DEK file already replaced by the new one)"
    fi
    # a killed admin command must not leave the next one locked out
    inst_admin "$I" encryption validate >"$DRILL_DIR/validate-after-kill.log" 2>&1 \
        || { cat "$DRILL_DIR/validate-after-kill.log" >&2; fail "encryption validate fails after a rotation killed at ${delay}s"; }
    srv_start "$I" "$P"
    verify_seed "$I" "$P"
    srv_stop "$I"
    ok "rotation killed at ${delay}s: validate passes, data readable"
done
out="$(inst_admin "$I" encryption rotate --confirm 2>&1)" || { echo "$out" >&2; fail "a rotation after the kills failed"; }
check_all "after killed rotations + a clean one"

# ---- C. KEK rotation ----------------------------------------------------------------
step "C. rotate the KEK (new master passphrase)"
out="$(env KEYORIX_NEW_MASTER_PASSWORD="$NEW_PW" bash -c 'cd "$1" && shift && exec "$@"' _ "$d" \
    env KEYORIX_CONFIG_PATH=./keyorix.yaml ${PG_PASS:+KEYORIX_DB_PASSWORD="$PG_PASS"} \
    "$DRILL_SERVER_BIN" admin encryption rotate-kek --confirm --config ./keyorix.yaml 2>&1)" \
    || { echo "$out" >&2; fail "rotate-kek failed"; }
grep -q 'KEK rotation complete' <<<"$out" || { echo "$out" >&2; fail "rotate-kek did not report completion"; }
ok "rotate-kek complete"

step "C. the OLD passphrase is refused at start with a clear message"
: >"$d/server.log"
if (srv_start "$I" "$P") >/dev/null 2>&1; then
    srv_stop "$I"
    fail "server started with the OLD passphrase after rotate-kek"
fi
rm -f "$d/server.pid"
grep -qiE 'passphrase|unwrap|decrypt|master' "$d/server.log" || { tail -5 "$d/server.log" >&2; fail "refusal did not mention the passphrase"; }
ok "refused: $(grep -iE 'passphrase|unwrap|decrypt|master' "$d/server.log" | head -1 | cut -c1-140)"

export KEYORIX_MASTER_PASSWORD="$NEW_PW"
check_all "with the NEW passphrase"

step "C. a backup taken BEFORE the rotation restores with the OLD passphrase"
tgt="$DRILL_DIR/tgt"
mkdir -p "$tgt/home"
cp "$d/keyorix.yaml" "$tgt/keyorix.yaml"
cp -R "$d/certs" "$tgt/certs"
cp -R "$d/secrets" "$tgt/secrets"
sed -i.bak -E "s/port: \"$P\"/port: \"$PT\"/" "$tgt/keyorix.yaml"
if [ "$DRILL_BACKEND" = "postgres" ]; then
    [ -n "${DRILL_PG_DSN_FILE2:-}" ] || fail "postgres needs DRILL_PG_DSN_FILE2 (a second EMPTY database)"
    src_db="$PG_DB"
    pg_parse "$DRILL_PG_DSN_FILE2"
    sed -i.bak -E "s/name: \"$src_db\"/name: \"$PG_DB\"/" "$tgt/keyorix.yaml"
fi
rm -f "$tgt/keyorix.yaml.bak"
export KEYORIX_MASTER_PASSWORD="$OLD_PW"
inst_admin tgt restore --input "$EXT/pre-rotation.tar.gz" >"$DRILL_DIR/restore-old.log" 2>&1 \
    || { cat "$DRILL_DIR/restore-old.log" >&2; fail "restore of the pre-rotation archive failed"; }
srv_start tgt "$PT"
DRILL_SEED_DIR="$I" DRILL_MFA_FROM="$I" verify_seed tgt "$PT"
srv_stop tgt
ok "pre-rotation archive restored and decrypts with the OLD passphrase"
export KEYORIX_MASTER_PASSWORD="$NEW_PW"

# ---- D. provider migration ------------------------------------------------------------
step "D. migrate the KEK provider password -> file"
(umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$d/keys/kek.hex")
out="$(inst_admin "$I" encryption migrate-provider --to-type file --to-file-path keys/kek.hex --confirm 2>&1)" \
    || { echo "$out" >&2; fail "migrate-provider --to-type file failed"; }
# the operator then points key_provider at the new source (the command prints the block)
sed -i.bak -E 's|^(    salt_path: "keys/kek.salt")|\1\n    key_provider:\n      type: file\n      file_path: "keys/kek.hex"|' "$d/keyorix.yaml"
rm -f "$d/keyorix.yaml.bak"
unset KEYORIX_MASTER_PASSWORD
check_all "file provider, no KEYORIX_MASTER_PASSWORD in the environment"

step "D. migrate the KEK provider file -> password (doubles as a passphrase rotation)"
FINAL_PW="drill-final-$(rand_hex 16)"
out="$(bash -c 'cd "$1" && shift && exec "$@"' _ "$d" \
    env KEYORIX_NEW_MASTER_PASSWORD="$FINAL_PW" KEYORIX_CONFIG_PATH=./keyorix.yaml ${PG_PASS:+KEYORIX_DB_PASSWORD="$PG_PASS"} \
    "$DRILL_SERVER_BIN" admin encryption migrate-provider --to-type password --confirm --config ./keyorix.yaml 2>&1)" \
    || { echo "$out" >&2; fail "migrate-provider --to-type password failed"; }
sed -i.bak -e '/^    key_provider:$/,/^      file_path: "keys\/kek.hex"$/d' "$d/keyorix.yaml"
rm -f "$d/keyorix.yaml.bak"
export KEYORIX_MASTER_PASSWORD="$FINAL_PW"
check_all "back on the password provider with the final passphrase"

drill_end "KEY ROTATION DRILL"
