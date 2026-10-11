#!/usr/bin/env bash
# entrypoint_test.sh — regression test for #241: entrypoint.sh's first-boot admin
# bootstrap used to pass the admin password to wget via --post-data, which puts it
# straight into the process's argv — visible to any process/user sharing the
# container's PID namespace via `ps`/`/proc/<pid>/cmdline` on literally every
# production first boot. It must now be written to a private (0600, owner-only)
# temp file and sent via --post-file instead.
#
# entrypoint.sh is a top-to-bottom `/bin/sh` script (no functions, no
# BASH_SOURCE guard), so it can't be sourced side-effect-free the way
# integrations/github-action/entrypoint_test.sh sources its target. Instead this
# test extracts the exact bootstrap `if [ -n "$KEYORIX_ADMIN_PASSWORD" ]; ...; fi`
# block verbatim and executes it under `sh` with a stub `wget` on PATH that
# records its own argv and snapshots whatever body it was asked to send — so the
# real production code path is exercised, not a reimplementation of it.
#
# Run directly: ./entrypoint_test.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
entrypoint="$script_dir/entrypoint.sh"

fail=0
note() { local msg="$1"; echo "ok   - $msg"; }
bad() { local msg="$1"; echo "FAIL - $msg"; fail=1; }

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/entrypoint-test.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

# --- Stub wget: log every argv token, and if invoked with --post-file=FILE,
# snapshot that file's content + mode before returning, so we can inspect what
# was actually about to be sent over the wire without a real network call. ---
stub_bin="$work_dir/bin"
mkdir -p "$stub_bin"

# Test-harness-only shim: on macOS, a bare `mktemp -d` (no template) ignores
# $TMPDIR and resolves to the Darwin per-user temp dir, which this sandboxed
# test runner may not be permitted to write to. Give it an explicit
# $TMPDIR-based template so the *unmodified* entrypoint.sh code under test can
# create its private tmpdir exactly as it does on the real (Linux/BusyBox)
# container, where plain `mktemp -d` already honors $TMPDIR/defaults to /tmp.
# (Built with printf rather than a heredoc: some sandboxed shells disallow the
# temp file bash normally creates internally to expand a heredoc's body.)
mktemp_stub=$'#!/bin/sh\n'
mktemp_stub+=$'real_mktemp="$(command -v /usr/bin/mktemp || command -v /bin/mktemp)"\n'
mktemp_stub+=$'case "$1" in\n'
mktemp_stub+=$'    -d) exec "$real_mktemp" -d "${TMPDIR:-/tmp}/entrypoint-test-inner.XXXXXX" ;;\n'
mktemp_stub+=$'    *) exec "$real_mktemp" "${TMPDIR:-/tmp}/entrypoint-test-inner.XXXXXX" ;;\n'
mktemp_stub+=$'esac\n'
printf '%s' "$mktemp_stub" >"$stub_bin/mktemp"
chmod +x "$stub_bin/mktemp"

argv_log="$work_dir/wget_argv.log"
payload_snapshot="$work_dir/payload_snapshot.json"
payload_path_file="$work_dir/payload_path.txt"
payload_mode_file="$work_dir/payload_mode.txt"
: >"$argv_log"

wget_stub=$'#!/bin/sh\n'
wget_stub+=$'printf \'SSL_CERT_FILE=%s\\n\' "${SSL_CERT_FILE:-}" >>"$WGET_ARGV_LOG"\n'
wget_stub+=$'for a in "$@"; do\n'
wget_stub+=$'    printf \'%s\\n\' "$a" >>"$WGET_ARGV_LOG"\n'
wget_stub+=$'    case "$a" in\n'
wget_stub+=$'        --post-file=*)\n'
wget_stub+=$'            f="${a#--post-file=}"\n'
wget_stub+=$'            cp "$f" "$WGET_PAYLOAD_SNAPSHOT"\n'
wget_stub+=$'            printf \'%s\\n\' "$f" >"$WGET_PAYLOAD_PATH_FILE"\n'
wget_stub+=$'            stat -c \'%a\' "$f" >"$WGET_PAYLOAD_MODE_FILE" 2>/dev/null || \\\n'
wget_stub+=$'                stat -f \'%Lp\' "$f" >"$WGET_PAYLOAD_MODE_FILE"\n'
wget_stub+=$'            ;;\n'
wget_stub+=$'    esac\n'
wget_stub+=$'done\n'
wget_stub+=$'exit 0\n'
printf '%s' "$wget_stub" >"$stub_bin/wget"
chmod +x "$stub_bin/wget"

# --- Extract the exact bootstrap block from entrypoint.sh verbatim. ---
# The single-quoted sed pattern intentionally matches the literal text
# '$KEYORIX_ADMIN_PASSWORD' as it appears in entrypoint.sh; it must not expand.
# shellcheck disable=SC2016
block="$(sed -n '/^if \[ -n "\$_kx_admin_password" \]; then$/,/^fi$/p' "$entrypoint")"
if [[ -z "$block" ]]; then
    echo "FAIL - could not locate the KEYORIX_ADMIN_PASSWORD bootstrap block in $entrypoint"
    exit 1
fi

password='S3cr3t-Test-P@ssw0rd!'

env -i \
    PATH="$stub_bin:/usr/bin:/bin" \
    TMPDIR="${TMPDIR:-/tmp}" \
    WGET_ARGV_LOG="$argv_log" \
    WGET_PAYLOAD_SNAPSHOT="$payload_snapshot" \
    WGET_PAYLOAD_PATH_FILE="$payload_path_file" \
    WGET_PAYLOAD_MODE_FILE="$payload_mode_file" \
    _kx_admin_password="$password" \
    KEYORIX_ADMIN_USERNAME="admin" \
    KEYORIX_ADMIN_EMAIL="admin@example.test" \
    _kx_bootstrap_token="test-bootstrap-token" \
    KEYORIX_LOCAL_URL="https://localhost:8080" \
    KEYORIX_LOCAL_CA_FILE="/app/tls/server.crt" \
    sh -c "$block"

# --- SECURE-DEFAULT-1: with TLS on, bootstrap goes to the https URL and
# verifies the server's own certificate (SSL_CERT_FILE for that wget only). ---
if grep -qxF -- "https://localhost:8080/system/init" "$argv_log"; then
    note "bootstrap POST goes to KEYORIX_LOCAL_URL"
else
    bad "bootstrap POST did not use KEYORIX_LOCAL_URL (https://localhost:8080/system/init)"
fi
if grep -qxF -- "SSL_CERT_FILE=/app/tls/server.crt" "$argv_log"; then
    note "bootstrap wget verifies with KEYORIX_LOCAL_CA_FILE"
else
    bad "bootstrap wget did not get SSL_CERT_FILE=KEYORIX_LOCAL_CA_FILE"
fi

# --- The password must never appear in wget's own argv. ---
if grep -qF -- "$password" "$argv_log"; then
    bad "admin password found in wget argv (this is the #241 leak)"
else
    note "admin password absent from wget argv"
fi

if grep -qF -- "test-bootstrap-token" "$argv_log"; then
    bad "bootstrap token found in wget argv"
else
    note "bootstrap token absent from wget argv"
fi

# --- ...but it must still reach the request body, via the --post-file. ---
if [[ ! -s "$payload_snapshot" ]]; then
    bad "wget was never invoked with --post-file; bootstrap payload was not captured"
elif grep -qF -- "$password" "$payload_snapshot"; then
    note "admin password present in the POST body sent via --post-file"
else
    bad "admin password missing from the captured POST body"
fi

if grep -q '"username":"admin"' "$payload_snapshot" && \
   grep -q '"email":"admin@example.test"' "$payload_snapshot"; then
    note "username/email still populated correctly in the POST body"
else
    bad "username/email missing or malformed in the POST body"
fi

# --- The payload file must have been private (owner-only) while it existed. ---
if [[ -f "$payload_mode_file" ]]; then
    mode="$(cat "$payload_mode_file")"
    if [[ "$mode" = "600" ]]; then
        note "payload temp file was created with mode 0600"
    else
        bad "payload temp file mode was '$mode', expected 600"
    fi
fi

# --- The temp file (and its containing dir) must be cleaned up afterwards. ---
if [[ -f "$payload_path_file" ]]; then
    payload_path="$(cat "$payload_path_file")"
    payload_dir="$(dirname "$payload_path")"
    if [[ -e "$payload_path" ]]; then
        bad "bootstrap payload file was not removed after use: $payload_path"
    else
        note "bootstrap payload file was removed after use"
    fi
    if [[ -e "$payload_dir" ]]; then
        bad "bootstrap temp directory was not removed after use: $payload_dir"
    else
        note "bootstrap temp directory was removed after use"
    fi
fi

# --- SECURE-DEFAULT-1: KEYORIX_CONFIG_SOURCE is copied to KEYORIX_CONFIG_PATH
# at 0600 (#2922), and arguments run instead of the server (`compose run`). ---
cfg_dir="$work_dir/cfg"
mkdir -p "$cfg_dir"
printf 'server: {}\n' >"$cfg_dir/source.yaml"
chmod 664 "$cfg_dir/source.yaml"
ran_marker="$work_dir/ran-args"
env -i PATH="$stub_bin:/usr/bin:/bin" TMPDIR="${TMPDIR:-/tmp}" \
    KEYORIX_CONFIG_SOURCE="$cfg_dir/source.yaml" \
    KEYORIX_CONFIG_PATH="$cfg_dir/keyorix.yaml" \
    sh "$entrypoint" touch "$ran_marker"
if [[ -f "$ran_marker" ]]; then
    note "arguments run instead of the server"
else
    bad "entrypoint with arguments did not run them"
fi
copy_mode="$(stat -c '%a' "$cfg_dir/keyorix.yaml" 2>/dev/null || stat -f '%Lp' "$cfg_dir/keyorix.yaml" 2>/dev/null || echo missing)"
if [[ "$copy_mode" = "600" ]] && cmp -s "$cfg_dir/source.yaml" "$cfg_dir/keyorix.yaml"; then
    note "KEYORIX_CONFIG_SOURCE copied to KEYORIX_CONFIG_PATH at 0600"
else
    bad "config copy missing, different or mode '$copy_mode' (want 0600)"
fi
if env -i PATH="$stub_bin:/usr/bin:/bin" KEYORIX_CONFIG_SOURCE="$cfg_dir/source.yaml" sh "$entrypoint" true 2>/dev/null; then
    bad "KEYORIX_CONFIG_SOURCE without KEYORIX_CONFIG_PATH did not fail"
else
    note "KEYORIX_CONFIG_SOURCE without KEYORIX_CONFIG_PATH fails"
fi

# --- #3025: when the bootstrap call keeps failing the entrypoint must exit
# non-zero (container fails loudly), never fall through to "healthy but
# unusable". wget always fails here; sleep is stubbed so the retries are instant. ---
fail_bin="$work_dir/failbin"
mkdir -p "$fail_bin"
cp "$stub_bin/mktemp" "$fail_bin/mktemp"
printf '#!/bin/sh\nexit 1\n' >"$fail_bin/wget"
printf '#!/bin/sh\nexit 0\n' >"$fail_bin/sleep"
chmod +x "$fail_bin/wget" "$fail_bin/sleep"

set +e
env -i \
    PATH="$fail_bin:/usr/bin:/bin" \
    TMPDIR="${TMPDIR:-/tmp}" \
    _kx_admin_password="$password" \
    _kx_bootstrap_token="test-bootstrap-token" \
    KEYORIX_BOOTSTRAP_ATTEMPTS=3 \
    sh -c "$block" >"$work_dir/fail_out.txt" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 0 ]] && grep -q "attempt 3/3 failed" "$work_dir/fail_out.txt" && grep -q "ERROR: admin bootstrap did not complete" "$work_dir/fail_out.txt"; then
    note "persistent bootstrap failure retries, logs, and exits non-zero (rc=$rc)"
else
    bad "persistent bootstrap failure did not exit non-zero with logged retries (rc=$rc)"
fi

# --- Password set without a bootstrap token is also fatal, not a silent skip. ---
set +e
env -i PATH="$fail_bin:/usr/bin:/bin" TMPDIR="${TMPDIR:-/tmp}" \
    _kx_admin_password="$password" \
    sh -c "$block" >"$work_dir/notoken_out.txt" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 0 ]] && grep -q "ERROR: KEYORIX_ADMIN_PASSWORD is set but" "$work_dir/notoken_out.txt"; then
    note "admin password without bootstrap token exits non-zero"
else
    bad "admin password without bootstrap token did not fail (rc=$rc)"
fi

# --- The credentials may come from KEYORIX_ADMIN_PASSWORD_FILE /
# KEYORIX_BOOTSTRAP_TOKEN_FILE (Docker secrets, Kubernetes Secret volumes): the
# entrypoint must resolve them before the bootstrap, not only look at the plain
# variables. Runs the real resolve_secret function plus the real bootstrap block.
# Test-only shim: BSD stat (macOS) has no -c, so translate the three formats the
# function uses; a GNU/busybox stat is used as is. ---
stat_stub=$'#!/bin/sh\n'
stat_stub+=$'if /usr/bin/stat -c %a / >/dev/null 2>&1; then exec /usr/bin/stat "$@"; fi\n'
stat_stub+=$'[ "$1" = "-L" ] && shift\n'
stat_stub+=$'fmt="$2"; f="$3"\n'
stat_stub+=$'case "$fmt" in\n'
stat_stub+=$'    %a) exec /usr/bin/stat -L -f %Lp "$f" ;;\n'
stat_stub+=$'    *) exec /usr/bin/stat -L -f "$fmt" "$f" ;;\n'
stat_stub+=$'esac\n'
printf '%s' "$stat_stub" >"$stub_bin/stat"
chmod +x "$stub_bin/stat"

resolver="$(sed -n '/^# --- BEGIN resolve_secret/,/^# --- END resolve_secret ---$/p' "$entrypoint")"
if [[ -z "$resolver" ]]; then
    echo "FAIL - could not locate resolve_secret in $entrypoint"
    exit 1
fi
secret_dir="$work_dir/secrets"
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
printf '%s\n' "$password" >"$secret_dir/admin_password"
printf '%s\n' "file-bootstrap-token" >"$secret_dir/bootstrap_token"
chmod 600 "$secret_dir/admin_password" "$secret_dir/bootstrap_token"
: >"$argv_log"
: >"$payload_snapshot"
set +e
env -i \
    PATH="$stub_bin:/usr/bin:/bin" \
    TMPDIR="${TMPDIR:-/tmp}" \
    WGET_ARGV_LOG="$argv_log" \
    WGET_PAYLOAD_SNAPSHOT="$payload_snapshot" \
    WGET_PAYLOAD_PATH_FILE="$payload_path_file" \
    WGET_PAYLOAD_MODE_FILE="$payload_mode_file" \
    KEYORIX_ADMIN_PASSWORD_FILE="$secret_dir/admin_password" \
    KEYORIX_BOOTSTRAP_TOKEN_FILE="$secret_dir/bootstrap_token" \
    sh -c "$resolver
resolve_secret KEYORIX_ADMIN_PASSWORD _kx_admin_password || exit 1
resolve_secret KEYORIX_BOOTSTRAP_TOKEN _kx_bootstrap_token || exit 1
$block" >"$work_dir/file_out.txt" 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]] && grep -qF -- '"bootstrap_token":"file-bootstrap-token"' "$payload_snapshot" \
    && grep -qF -- "$password" "$payload_snapshot" \
    && ! grep -qF -- "file-bootstrap-token" "$argv_log"; then
    note "KEYORIX_ADMIN_PASSWORD_FILE and KEYORIX_BOOTSTRAP_TOKEN_FILE are honoured by the bootstrap (rc=$rc)"
else
    bad "bootstrap ignored KEYORIX_*_FILE credentials (rc=$rc): $(cat "$work_dir/file_out.txt")"
fi

if [[ "$fail" -ne 0 ]]; then
    echo
    echo "entrypoint_test.sh: FAILED"
    exit 1
fi

echo
echo "entrypoint_test.sh: all checks passed"
