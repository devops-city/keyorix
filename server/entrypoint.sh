#!/bin/sh
set -e

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
./keyorix-server &
SERVER_PID=$!

# Always re-foreground the server on exit so signals propagate to it.
trap 'kill -TERM "$SERVER_PID" 2>/dev/null' TERM INT

echo "Waiting for server to be ready..."
for _ in $(seq 1 30); do
    if wget --quiet --spider http://localhost:8080/health 2>/dev/null; then
        echo "Server is ready"
        break
    fi
    sleep 1
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
        echo "WARN: KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN is not — skipping"
        echo "WARN: auto-bootstrap (the server-generated random token can't be read back here)."
        echo "WARN: Set KEYORIX_BOOTSTRAP_TOKEN, or initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
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
        wget --quiet -O- \
            --header='Content-Type: application/json' \
            --post-file="$BOOTSTRAP_PAYLOAD_FILE" \
            http://localhost:8080/system/init 2>/dev/null || \
            echo "Bootstrap call failed (server may already be initialised) — continuing."
        rm -rf "$BOOTSTRAP_TMPDIR"
        trap - EXIT
    fi
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
