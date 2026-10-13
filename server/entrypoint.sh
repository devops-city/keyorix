#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# Container preparation (SECURE-DEFAULT-1). Every step is opt-in through the
# environment, so a deployment that sets none of these variables behaves
# exactly as before.
#
# KEYORIX_CONFIG_SOURCE: a read-only, orchestrator-mounted config. A compose
#   bind mount keeps the host's owner and mode (typically uid 1000, 0664), which
#   the startup file-permission check and `admin validate --posture` flag
#   (#2922). Copy it to KEYORIX_CONFIG_PATH as this user at 0600 on every
#   start, so an edit to the source takes effect on the next restart.
# KEYORIX_INIT_SECURE_FILES=true: generate the TLS certificate/key and metrics
#   token the config references, if missing (`admin init --secure-files`;
#   existing files are kept). KEYORIX_TLS_DNS_NAMES adds space-separated DNS
#   names to a generated certificate; KEYORIX_PUBLIC_CA_FILE receives a 0644
#   copy of the certificate for a proxy that must trust it (the web container).
# KEYORIX_LOCAL_URL / KEYORIX_LOCAL_CA_FILE: how this script reaches its own
#   server (default http://localhost:8080). With TLS on, set the https URL and
#   the certificate to verify it with; it is used only for this script's own
#   requests, never exported to the server (Go would read SSL_CERT_FILE too).
#
# With arguments (`docker compose run --rm backend ./keyorix-server admin ...`)
# the config copy is made and the arguments are run instead of the server.
# ---------------------------------------------------------------------------
# --- BEGIN public_cert (extracted verbatim by server/entrypoint_public_cert_test.go) ---
# require_regular_file NAME PATH: PATH (the value of env var NAME) must be a regular
# file (or a symlink to one): refuse a directory, FIFO or device (cp would block or
# copy something unintended).
require_regular_file() {
    if [ ! -f "$2" ] || [ ! -r "$2" ]; then
        echo "ERROR: $1=$2 is not a readable regular file" >&2
        return 1
    fi
}
# require_public_cert NAME FILE: FILE (about to be made world-readable) must be a PEM
# certificate bundle: at least one CERTIFICATE block, only blocks with base64 bodies
# (blank lines between blocks allowed), nothing else, no PRIVATE KEY block of any kind
# (RSA/EC/ENCRYPTED/PKCS#8), at most 256 KiB. Never prints file contents.
require_public_cert() {
    if [ "$(wc -c < "$2")" -gt 262144 ]; then
        echo "ERROR: $1 is larger than 256 KiB -- refusing to publish it as a certificate" >&2
        return 1
    fi
    if grep -q 'PRIVATE KEY' "$2"; then
        echo "ERROR: $1 contains a PRIVATE KEY -- refusing to copy it to a world-readable file (point it at the public certificate)" >&2
        return 1
    fi
    if ! awk '
        { sub(/\r$/, "") }
        $0 == "-----BEGIN CERTIFICATE-----" { if (inb) bad = 1; inb = 1; n++; next }
        $0 == "-----END CERTIFICATE-----" { if (!inb) bad = 1; inb = 0; next }
        inb && /^[A-Za-z0-9+\/=]+$/ { next }
        !inb && /^$/ { next }
        { bad = 1 }
        END { exit (bad || inb || n == 0) ? 1 : 0 }
    ' "$2"; then
        echo "ERROR: $1 is not a PEM certificate bundle (only CERTIFICATE blocks are allowed) -- refusing to copy it to a world-readable file" >&2
        return 1
    fi
}
# --- END public_cert ---

if [ -n "$KEYORIX_CONFIG_SOURCE" ]; then
    : "${KEYORIX_CONFIG_PATH:?KEYORIX_CONFIG_SOURCE is set, so KEYORIX_CONFIG_PATH must name the private copy}"
    (umask 077 && cp "$KEYORIX_CONFIG_SOURCE" "$KEYORIX_CONFIG_PATH.tmp")
    chmod 600 "$KEYORIX_CONFIG_PATH.tmp"
    mv -f "$KEYORIX_CONFIG_PATH.tmp" "$KEYORIX_CONFIG_PATH"
fi

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

if [ "$KEYORIX_INIT_SECURE_FILES" = "true" ]; then
    set --
    if [ -n "$KEYORIX_CONFIG_PATH" ]; then
        set -- --config "$KEYORIX_CONFIG_PATH"
    fi
    for name in $KEYORIX_TLS_DNS_NAMES; do
        set -- "$@" --tls-dns-name "$name"
    done
    /app/keyorix-server admin init --secure-files "$@"
    if [ -n "$KEYORIX_PUBLIC_CA_FILE" ]; then
        : "${KEYORIX_LOCAL_CA_FILE:?KEYORIX_PUBLIC_CA_FILE needs KEYORIX_LOCAL_CA_FILE (the certificate to copy)}"
        # The copy is world-readable on a volume shared with the web container, so
        # it must be a certificate bundle and nothing else. Copy privately (0600)
        # first and check the COPY, so the file cannot change between check and use.
        require_regular_file KEYORIX_LOCAL_CA_FILE "$KEYORIX_LOCAL_CA_FILE" || exit 1
        (umask 077 && cp "$KEYORIX_LOCAL_CA_FILE" "$KEYORIX_PUBLIC_CA_FILE.tmp")
        if ! require_public_cert KEYORIX_LOCAL_CA_FILE "$KEYORIX_PUBLIC_CA_FILE.tmp"; then
            rm -f "$KEYORIX_PUBLIC_CA_FILE.tmp"
            exit 1
        fi
        chmod 644 "$KEYORIX_PUBLIC_CA_FILE.tmp"
        mv -f "$KEYORIX_PUBLIC_CA_FILE.tmp" "$KEYORIX_PUBLIC_CA_FILE"
    fi
fi

# 127.0.0.1, not localhost: busybox resolves localhost to ::1 first.
LOCAL_URL="${KEYORIX_LOCAL_URL:-http://127.0.0.1:8080}"
# local_wget: wget against this container's own server, verifying its TLS
# certificate with KEYORIX_LOCAL_CA_FILE when one is set.
local_wget() {
    if [ -n "$KEYORIX_LOCAL_CA_FILE" ]; then
        SSL_CERT_FILE="$KEYORIX_LOCAL_CA_FILE" wget "$@"
    else
        wget "$@"
    fi
}

echo "Starting Keyorix server..."

# --- BEGIN resolve_secret (extracted verbatim by server/entrypoint_secret_file_test.go) ---
# resolve_secret NAME OUT: NAME may come from the environment or, as NAME_FILE, from
# a mounted secret file (Docker secrets, Kubernetes Secret volume) -- the same rules
# as the server's own *_FILE support (internal/secretenv):
#   - both NAME and NAME_FILE set (non-empty) -> refuse (exit 1), no precedence;
#   - NAME_FILE unreadable / empty / not a regular file / over 1 MiB -> refuse;
#   - one trailing "\n", then one trailing "\r", is stripped (as the server and
#     --passphrase-file do);
#   - the file must not be accessible to "other", writable by its group, or carry
#     setuid/setgid/sticky; group-read (0440/0640) is accepted only for a file the
#     running user does not own whose group the process holds (fsGroup/group_add);
#   - neither the value nor the file contents are ever printed.
# The value goes into the shell variable OUT, which is unset first so it is never
# exported, even when a variable of that name came in with the environment. NAME and
# NAME_FILE are never modified: the server inherits exactly what the operator set
# (the file path, never the resolved value), and a compose file's empty
# NAME=${NAME:-} passthrough stays empty, so the server's own both-set check holds.
resolve_secret() {
    _rs_name="$1"
    _rs_out="$2"
    unset "$_rs_out"
    eval "_rs_direct=\${$_rs_name:-}"
    eval "_rs_path=\${${_rs_name}_FILE:-}"
    if [ -z "$_rs_path" ]; then
        eval "$_rs_out=\$_rs_direct"
        return 0
    fi
    if [ -n "$_rs_direct" ]; then
        echo "ERROR: both $_rs_name and ${_rs_name}_FILE are set; set exactly one" >&2
        return 1
    fi
    if [ ! -f "$_rs_path" ] || [ ! -r "$_rs_path" ]; then
        echo "ERROR: ${_rs_name}_FILE=$_rs_path is not a readable regular file" >&2
        return 1
    fi
    _rs_mode=$(stat -L -c '%a' "$_rs_path") || return 1
    _rs_uid=$(stat -L -c '%u' "$_rs_path") || return 1
    _rs_gid=$(stat -L -c '%g' "$_rs_path") || return 1
    _rs_other=${_rs_mode#"${_rs_mode%?}"}
    _rs_rest=${_rs_mode%?}
    _rs_group=${_rs_rest#"${_rs_rest%?}"}
    _rs_ok=1
    [ "${#_rs_mode}" -le 3 ] || _rs_ok=0                      # setuid/setgid/sticky
    [ "$_rs_other" = 0 ] || _rs_ok=0                          # any access for other
    [ $(( _rs_group & 2 )) -eq 0 ] || _rs_ok=0                # group-writable
    if [ "$_rs_ok" = 1 ] && [ $(( _rs_group & 5 )) -ne 0 ]; then
        # group-readable: only an orchestrator-owned file in a group we hold
        _rs_ok=0
        if [ "$_rs_uid" != "$(id -u)" ]; then
            for _rs_g in $(id -G); do
                [ "$_rs_g" = "$_rs_gid" ] && _rs_ok=1
            done
        fi
    fi
    if [ "$_rs_ok" != 1 ]; then
        echo "ERROR: ${_rs_name}_FILE=$_rs_path has mode $_rs_mode -- refusing to trust it (chmod 0600/0400, or mount it owned by another user, e.g. root, with a group the process belongs to and mode 0440)" >&2
        return 1
    fi
    _rs_nl='
'
    _rs_cr=$(printf '\r')
    # head -c caps the read at 1 MiB + 1; the trailing x protects the final newline
    # from command substitution. && (not ;) so a failed read fails here instead of
    # yielding printf's status.
    _rs_val=$(head -c 1048577 "$_rs_path" && printf x) || return 1
    _rs_val=${_rs_val%x}
    if [ "${#_rs_val}" -gt 1048576 ]; then
        echo "ERROR: ${_rs_name}_FILE=$_rs_path is too large" >&2
        return 1
    fi
    case "$_rs_val" in *"$_rs_nl") _rs_val=${_rs_val%"$_rs_nl"} ;; esac
    case "$_rs_val" in *"$_rs_cr") _rs_val=${_rs_val%"$_rs_cr"} ;; esac
    if [ -z "$_rs_val" ]; then
        echo "ERROR: ${_rs_name}_FILE=$_rs_path is empty" >&2
        return 1
    fi
    eval "$_rs_out=\$_rs_val"
    unset _rs_val _rs_direct
}
# --- END resolve_secret ---

# KEYORIX_BOOTSTRAP_TOKEN_FILE is also read by the server itself (it is passed
# through unchanged); resolve both credentials here before starting it so a bad
# setting fails the container at once and a _FILE-only deployment still
# auto-bootstraps. The values live only in these unexported shell variables.
resolve_secret KEYORIX_ADMIN_PASSWORD _kx_admin_password || exit 1
resolve_secret KEYORIX_BOOTSTRAP_TOKEN _kx_bootstrap_token || exit 1

# Run the server in the background so we can perform an optional first-boot admin
# bootstrap once it is healthy, then hand the process the foreground.
/app/keyorix-server &
SERVER_PID=$!

# Always re-foreground the server on exit so signals propagate to it.
trap 'kill -TERM "$SERVER_PID" 2>/dev/null' TERM INT

# Wait for REAL readiness (GET /health answering 2xx), not a fixed number of
# tries: a first boot runs DB migrations and key setup, which on a cold Postgres
# can take well over 30 s. Bounded by KEYORIX_READY_TIMEOUT seconds (default 180),
# logs progress every 10 s, and stops early if the server process dies.
# 127.0.0.1, not localhost: busybox resolves localhost to ::1 first.
READY_TIMEOUT="${KEYORIX_READY_TIMEOUT:-180}"
echo "Waiting for server to be ready (up to ${READY_TIMEOUT}s)..."
SERVER_READY=0
waited=0
while [ "$waited" -lt "$READY_TIMEOUT" ]; do
    if local_wget --quiet --spider "$LOCAL_URL/health" 2>/dev/null; then
        SERVER_READY=1
        echo "Server is ready after ${waited}s"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: keyorix-server exited before becoming ready" >&2
        wait "$SERVER_PID" || exit $?
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
    if [ $((waited % 10)) -eq 0 ]; then
        echo "Still waiting for server to be ready (${waited}s/${READY_TIMEOUT}s)..."
    fi
done

# First-boot admin bootstrap (optional, idempotent). Only runs when an admin
# password is supplied via the environment (KEYORIX_ADMIN_PASSWORD or
# KEYORIX_ADMIN_PASSWORD_FILE) — there are NO hardcoded credentials.
# POST /system/init is safe to call repeatedly: it reports already_initialized
# and changes nothing once an admin exists. /system/init always requires a
# matching bootstrap token (operator-set via KEYORIX_BOOTSTRAP_TOKEN or _FILE, or else a
# random one the server generates and only logs) — without KEYORIX_BOOTSTRAP_TOKEN
# set here, this call has no token to send and is rejected.
if [ -n "$_kx_admin_password" ]; then
    ADMIN_USER="${KEYORIX_ADMIN_USERNAME:-admin}"
    ADMIN_EMAIL="${KEYORIX_ADMIN_EMAIL:-admin@keyorix.local}"
    if [ -z "$_kx_bootstrap_token" ]; then
        # Fail loudly: an admin password was requested but cannot be applied, and a
        # container that reports healthy with no usable login is worse than a crash.
        echo "ERROR: KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN (or KEYORIX_BOOTSTRAP_TOKEN_FILE) is not, so the" >&2
        echo "ERROR: admin cannot be bootstrapped (the server-generated random token can't be read back here)." >&2
        echo "ERROR: Set KEYORIX_BOOTSTRAP_TOKEN, or unset KEYORIX_ADMIN_PASSWORD and initialise manually (keyorix system init)." >&2
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        exit 1
    else
        echo "Bootstrapping admin user '$ADMIN_USER' (idempotent)..."
        # Write the POST body (which embeds the admin password and the bootstrap
        # token, sent as the body's bootstrap_token field rather than a header) to a
        # private temp file and hand it to wget via --post-file instead of
        # --post-data/--header: argv is visible to any process sharing this
        # container's PID namespace via `ps`/`/proc/<pid>/cmdline`, so passing
        # either inline as a wget flag would leak it on every first boot. `mktemp -d` creates the directory with
        # 0700 permissions (only this UID can traverse it), and the payload file
        # inside it is additionally chmod'd 0600 as defense in depth. The whole
        # directory is removed as soon as the request completes (or the shell exits).
        BOOTSTRAP_TMPDIR=$(mktemp -d)
        trap 'rm -rf "$BOOTSTRAP_TMPDIR"' EXIT
        BOOTSTRAP_PAYLOAD_FILE="$BOOTSTRAP_TMPDIR/bootstrap.json"
        : > "$BOOTSTRAP_PAYLOAD_FILE"
        chmod 600 "$BOOTSTRAP_PAYLOAD_FILE"
        # Escape JSON special characters (backslash then double-quote) before
        # interpolating values into the payload — prevents malformed JSON or
        # JSON-injection if the password contains \ or " characters.
        json_escape() { local v; v="$1"; printf '%s' "$v" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
        ADMIN_USER_J=$(json_escape "$ADMIN_USER")
        ADMIN_EMAIL_J=$(json_escape "$ADMIN_EMAIL")
        ADMIN_PASS_J=$(json_escape "$_kx_admin_password")
        BOOTSTRAP_TOKEN_J=$(json_escape "$_kx_bootstrap_token")
        printf '{"username":"%s","email":"%s","password":"%s","display_name":"Administrator","bootstrap_token":"%s"}' \
            "$ADMIN_USER_J" "$ADMIN_EMAIL_J" "$ADMIN_PASS_J" "$BOOTSTRAP_TOKEN_J" > "$BOOTSTRAP_PAYLOAD_FILE"
        unset ADMIN_PASS_J BOOTSTRAP_TOKEN_J
        # Bounded, logged retry. /system/init is idempotent (already_initialized
        # is a 200), so retrying is safe. If it still cannot complete, stop the
        # server and exit non-zero: never "healthy but unusable" (#3025).
        BOOTSTRAP_ATTEMPTS="${KEYORIX_BOOTSTRAP_ATTEMPTS:-10}"
        BOOTSTRAP_OK=0
        attempt=1
        while [ "$attempt" -le "$BOOTSTRAP_ATTEMPTS" ]; do
            # Self-contained (entrypoint_test.sh runs this block on its own): verify
            # this server's own certificate when KEYORIX_LOCAL_CA_FILE is set; the
            # subshell keeps SSL_CERT_FILE away from everything else.
            if (
                if [ -n "$KEYORIX_LOCAL_CA_FILE" ]; then SSL_CERT_FILE="$KEYORIX_LOCAL_CA_FILE"; export SSL_CERT_FILE; fi
                wget --quiet -O- \
                    --header='Content-Type: application/json' \
                    --post-file="$BOOTSTRAP_PAYLOAD_FILE" \
                    "${KEYORIX_LOCAL_URL:-http://127.0.0.1:8080}/system/init"
            ) >/dev/null 2>&1; then
                BOOTSTRAP_OK=1
                break
            fi
            echo "Bootstrap attempt ${attempt}/${BOOTSTRAP_ATTEMPTS} failed; retrying in 3s..."
            attempt=$((attempt + 1))
            sleep 3
        done
        if [ "$BOOTSTRAP_OK" -ne 1 ]; then
            rm -rf "$BOOTSTRAP_TMPDIR"
            echo "ERROR: admin bootstrap did not complete after ${BOOTSTRAP_ATTEMPTS} attempts" >&2
            echo "ERROR: (server ready=${SERVER_READY}). Check KEYORIX_BOOTSTRAP_TOKEN matches and the server logs above." >&2
            kill -TERM "$SERVER_PID" 2>/dev/null
            wait "$SERVER_PID" 2>/dev/null
            exit 1
        fi
        echo "Admin bootstrap complete."
        rm -rf "$BOOTSTRAP_TMPDIR"
        trap - EXIT
    fi
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
