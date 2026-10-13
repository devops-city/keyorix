#!/bin/sh
# init-secrets.sh -- create the Docker-secrets files for the self-hosted compose stack.
#
#   ./scripts/selfhost/init-secrets.sh                  # new install: generate every secret
#   ./scripts/selfhost/init-secrets.sh --from-env .env  # upgrade: move the values out of .env
#
# Creates, under ./secrets (or --dir DIR / $KEYORIX_SECRETS_DIR):
#   db_password  master_password  admin_password  bootstrap_token
# and records KEYORIX_SECRETS_GID in .env (or --env-file FILE).
#
# - Files are written 0640 owned by you and your primary group. Compose bind-mounts a
#   file secret as-is and ignores its uid/gid/mode, so the containers read it by
#   joining that group (group_add: KEYORIX_SECRETS_GID in docker-compose.yml). Nothing
#   is ever world-readable.
# - An existing file is NEVER overwritten (changing master_password after first boot
#   makes every stored secret undecryptable; the DB password must match the existing
#   postgres volume). Delete a file yourself if you really mean to regenerate it.
# - --from-env copies the four values from an existing .env byte for byte, so an
#   upgrade keeps the same master and database passwords.
# - No secret value is ever printed.
set -eu

dir="${KEYORIX_SECRETS_DIR:-./secrets}"
env_file=".env"
from_env=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) dir="$2"; shift 2 ;;
        --env-file) env_file="$2"; shift 2 ;;
        --from-env) from_env="$2"; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) echo "init-secrets: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Value of KEY in a dotenv-style file: text after the first "=", one pair of
# surrounding single or double quotes removed. Prints nothing if absent/empty.
env_value() {
    [ -n "$from_env" ] && [ -f "$from_env" ] || return 0
    _line=$(grep -E "^[[:space:]]*$1=" "$from_env" | tail -n 1) || return 0
    _v=${_line#*=}
    case $_v in
        \"*\") _v=${_v#\"}; _v=${_v%\"} ;;
        \'*\') _v=${_v#\'}; _v=${_v%\'} ;;
    esac
    printf '%s' "$_v"
}

random_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 36 | tr -d '/+=\n'
    else
        head -c 36 /dev/urandom | base64 | tr -d '/+=\n'
    fi
}

umask 027
mkdir -p "$dir"
chmod 750 "$dir"

gid=$(id -g)
if [ "$gid" = "0" ]; then
    echo "init-secrets: WARNING: your primary group is root (gid 0), so the containers would join" >&2
    echo "init-secrets: the root group to read the files. Run this as a regular user instead." >&2
fi

# The first admin's identity as the compose stack will pass it to the server
# (KEYORIX_ADMIN_USERNAME / KEYORIX_ADMIN_EMAIL: the shell, then $env_file, then the
# compose defaults). The server refuses a first-admin password that embeds the
# username, the email's local part or the display name "Administrator", compared
# case-insensitively (rules.containsPersonalInfo), and an admin that cannot be
# bootstrapped crash-loops the backend (#3201).
identity_value() { # KEY default
    eval "_iv=\${$1:-}"
    if [ -z "$_iv" ] && [ -f "$env_file" ]; then
        _line=$(grep -E "^[[:space:]]*$1=" "$env_file" | tail -n 1) || _line=""
        _iv=${_line#*=}
        case $_iv in
            \"*\") _iv=${_iv#\"}; _iv=${_iv%\"} ;;
            \'*\') _iv=${_iv#\'}; _iv=${_iv%\'} ;;
        esac
    fi
    printf '%s' "${_iv:-$2}"
}
admin_user=$(identity_value KEYORIX_ADMIN_USERNAME admin)
admin_email=$(identity_value KEYORIX_ADMIN_EMAIL admin@keyorix.local)

# embedded_identity PASSWORD: prints what the password embeds and returns 0, or
# returns 1 when it embeds none of the admin's identity. Never prints the password.
embedded_identity() {
    _pw=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    _local=""
    case $admin_email in *@*) _local=${admin_email%%@*} ;; esac
    for _what in "username:$admin_user" "email local part:$_local" "display name:Administrator"; do
        _cand=$(printf '%s' "${_what#*:}" | tr '[:upper:]' '[:lower:]')
        [ "${#_cand}" -ge 3 ] || continue
        case $_pw in *"$_cand"*) printf 'the %s "%s"' "${_what%%:*}" "${_what#*:}"; return 0 ;; esac
    done
    return 1
}

write_secret() { # file_name ENV_NAME kind
    _path="$dir/$1"
    if [ -e "$_path" ]; then
        echo "kept     $_path (already exists; not overwritten)"
        if [ "$3" = "admin" ]; then
            _kept=$(head -n 1 "$_path" 2>/dev/null) || _kept=""
            if [ -n "$_kept" ] && _emb=$(embedded_identity "$_kept"); then
                echo "init-secrets: WARNING: $_path contains $_emb; the server refuses such a first-admin" >&2
                echo "init-secrets: password, so a NEW install (no admin yet) will not bootstrap. Replace the file's content first." >&2
            fi
        fi
        return 0
    fi
    _val=$(env_value "$2")
    _src="generated"
    if [ -n "$_val" ]; then
        _src="from $from_env"
        if [ "$3" = "admin" ] && _emb=$(embedded_identity "$_val"); then
            # Not an error: an install that already has its admin boots fine with it
            # (--from-env is an upgrade path). A fresh one would crash-loop.
            echo "init-secrets: WARNING: $2 in $from_env contains $_emb; the server refuses such a first-admin" >&2
            echo "init-secrets: password, so a NEW install (no admin yet) will not bootstrap. Set a different one before 'docker compose up'." >&2
        fi
    elif [ "$3" = "admin" ]; then
        # Satisfies the server's admin-password policy (16+ chars, upper, lower, digit,
        # special) whatever the random part contains, and is drawn again in the rare
        # case that the random part embeds the admin's username (#3201).
        _n=0
        while :; do
            _val="$(random_token)-Aa1!"
            embedded_identity "$_val" >/dev/null || break
            _n=$((_n + 1))
            [ "$_n" -lt 20 ] || { echo "init-secrets: ERROR: could not generate an admin password that avoids the username '$admin_user'" >&2; exit 1; }
        done
    else
        _val=$(random_token)
    fi
    ( umask 037; printf '%s\n' "$_val" > "$_path" )
    chmod 640 "$_path"
    echo "created  $_path ($_src)"
}

write_secret db_password KEYORIX_DB_PASSWORD plain
write_secret master_password KEYORIX_MASTER_PASSWORD plain
write_secret admin_password KEYORIX_ADMIN_PASSWORD admin
write_secret bootstrap_token KEYORIX_BOOTSTRAP_TOKEN plain

# Record the group the containers must join. Replace an existing line in place.
touch "$env_file"
if grep -q '^KEYORIX_SECRETS_GID=' "$env_file"; then
    _tmp="$env_file.tmp.$$"
    sed "s/^KEYORIX_SECRETS_GID=.*/KEYORIX_SECRETS_GID=$gid/" "$env_file" > "$_tmp"
    cat "$_tmp" > "$env_file"
    rm -f "$_tmp"
else
    printf 'KEYORIX_SECRETS_GID=%s\n' "$gid" >> "$env_file"
fi
echo "updated  $env_file (KEYORIX_SECRETS_GID=$gid)"

if [ -n "$from_env" ]; then
    echo
    echo "Migrated. The compose file no longer reads these from the environment; remove the"
    echo "plaintext lines from $from_env so the secrets live only in $dir:"
    echo "  KEYORIX_DB_PASSWORD  KEYORIX_MASTER_PASSWORD  KEYORIX_ADMIN_PASSWORD  KEYORIX_BOOTSTRAP_TOKEN"
fi
echo
echo "The first admin's password is in $dir/admin_password (user: KEYORIX_ADMIN_USERNAME, default admin)."
echo "Back up $dir/master_password separately: losing it makes every stored secret undecryptable."

# The server container runs as uid 1001 and REFUSES a group-readable secret file that
# its own uid owns (the permission rule never trusts a file the process itself could
# chmod). On a host where your uid is also 1001 the 0640 files above would be refused,
# so say so now instead of at `docker compose up`. Another owner is fine: the group
# bit is what the container uses.
#
# INIT_SECRETS_SERVER_UID names the uid to refuse. Default 1001 (the shipped image). Set it
# only if you rebuilt the image with a different server uid (operator override), or from
# tests that must not run as the server uid. It must be a number: anything else is an error
# (a value that never matches would silently turn this check off).
server_uid="${INIT_SECRETS_SERVER_UID:-1001}"
case "$server_uid" in
    ''|*[!0-9]*)
        echo "init-secrets: ERROR: INIT_SECRETS_SERVER_UID must be a numeric uid, got '$server_uid'" >&2
        exit 1
        ;;
esac
bad=""
for _f in db_password master_password admin_password bootstrap_token; do
    _owner=$(stat -c %u "$dir/$_f" 2>/dev/null || stat -f %u "$dir/$_f" 2>/dev/null || echo "")
    if [ "$_owner" = "$server_uid" ]; then
        bad="$bad $dir/$_f"
    fi
done
if [ -n "$bad" ]; then
    echo >&2
    echo "init-secrets: ERROR: these files are owned by uid $server_uid, the uid the server container runs as:" >&2
    echo "init-secrets:  $bad" >&2
    echo "init-secrets: the server refuses a group-readable secret it owns. Hand them to another owner and re-run:" >&2
    echo "init-secrets:   sudo chown root:$gid $dir/*" >&2
    echo "init-secrets: (or run this script as a different user)." >&2
    exit 1
fi
