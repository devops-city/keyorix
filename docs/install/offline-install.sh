#!/bin/sh
# offline-install.sh -- the INSTALL-WITH-AI.md procedure as a plain script, for an
# air-gapped host or a local model: no network access, and no secret is ever
# printed. Every secret is generated into a 0600 file and passed by path
# (KEYORIX_*_FILE); the two steps that must show a secret to a person (MFA
# enrolment, and the recovery key when there is no public key to encrypt it to)
# are printed as commands for the operator to run in their own terminal.
#
#   offline-install.sh setup --bin-dir DIR --admin-email EMAIL [--dir DIR]
#                            [--recipient AGE1_OR_SSH_PUB] [--http-port N] [--grpc-port N]
#   (operator: sign in and enrol MFA, as printed)
#   offline-install.sh finish [--dir DIR]   # stop, drop the bootstrap token, posture proof, start
#   offline-install.sh stop|start [--dir DIR]
#
# --bin-dir holds keyorix and keyorix-server (built with `make build`, or copied in
# from a connected machine). --dir defaults to ~/keyorix. Exits non-zero on the
# first failing step; nothing already created is overwritten by a re-run.
set -eu

die() { echo "offline-install: $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

phase="${1:-}"
[ -n "$phase" ] && shift
dir="$HOME/keyorix"
bin_dir=""
admin_email=""
recipient=""
http_port=8080
grpc_port=9090
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) dir="$2"; shift 2 ;;
        --bin-dir) bin_dir="$2"; shift 2 ;;
        --admin-email) admin_email="$2"; shift 2 ;;
        --recipient) recipient="$2"; shift 2 ;;
        --http-port) http_port="$2"; shift 2 ;;
        --grpc-port) grpc_port="$2"; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# Secrets reach the commands only as file paths. A plain KEYORIX_* value already
# in the environment would make them refuse ("both ... set"), so drop it here.
unset KEYORIX_MASTER_PASSWORD KEYORIX_BOOTSTRAP_TOKEN KEYORIX_ADMIN_PASSWORD
umask 077

health() {
    curl -fs --retry 30 --retry-connrefused --retry-delay 1 --cacert certs/server.crt \
        "https://localhost:$(port)/health" >/dev/null || die "server did not become healthy; see $dir/server.log"
    echo "server healthy on https://localhost:$(port)"
}

port() { sed -n 's/^ *port: "\([0-9]*\)".*/\1/p' keyorix.yaml | head -n 1; }

start_server() { # [bootstrap]
    [ -f server.pid ] && kill -0 "$(cat server.pid)" 2>/dev/null && die "server already running (pid $(cat server.pid))"
    touch server.log
    chmod 600 server.log
    if [ "${1:-}" = bootstrap ]; then
        KEYORIX_CONFIG_PATH=./keyorix.yaml KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password KEYORIX_BOOTSTRAP_TOKEN_FILE=secrets/bootstrap_token nohup ./bin/keyorix-server >> server.log 2>&1 &
    else
        KEYORIX_CONFIG_PATH=./keyorix.yaml KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password nohup ./bin/keyorix-server >> server.log 2>&1 &
    fi
    echo $! > server.pid
    health
}

stop_server() {
    [ -f server.pid ] || { echo "no server.pid: server not started by this script"; return 0; }
    pid=$(cat server.pid)
    if kill "$pid" 2>/dev/null; then
        i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
        kill -0 "$pid" 2>/dev/null && die "server (pid $pid) did not stop"
    fi
    rm -f server.pid
    echo "server stopped"
}

case "$phase" in
setup)
    [ -n "$bin_dir" ] || die "--bin-dir is required"
    [ -n "$admin_email" ] || die "--admin-email is required"
    [ -x "$bin_dir/keyorix" ] && [ -x "$bin_dir/keyorix-server" ] || die "$bin_dir must contain keyorix and keyorix-server"
    "$bin_dir/keyorix-server" admin generate-secrets --help >/dev/null 2>&1 ||
        die "$bin_dir/keyorix-server has no 'admin generate-secrets': build a newer one"
    [ -e "$dir/keyorix.yaml" ] && die "$dir already has a keyorix.yaml; use 'finish', or a new --dir"

    say "1. install directory $dir"
    mkdir -p "$dir"
    chmod 700 "$dir"
    cd "$dir"
    mkdir -p bin
    cp "$bin_dir/keyorix" "$bin_dir/keyorix-server" bin/

    say "2. secrets (0600 files, never printed)"
    ./bin/keyorix-server admin generate-secrets

    say "3. config, TLS certificate, metrics token"
    ./bin/keyorix-server admin init --config ./keyorix.yaml
    if [ "$http_port" != 8080 ] || [ "$grpc_port" != 9090 ]; then
        sed "s/port: \"8080\"/port: \"$http_port\"/; s/port: \"9090\"/port: \"$grpc_port\"/" keyorix.yaml > keyorix.yaml.new
        mv keyorix.yaml.new keyorix.yaml
        echo "ports: http $http_port, grpc $grpc_port"
    fi

    say "4. encryption keys and database"
    KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin encryption init --config ./keyorix.yaml
    KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin migrate --config ./keyorix.yaml

    if [ -n "$recipient" ]; then
        say "5. admin recovery key, encrypted to $recipient"
        KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml --recipient "$recipient" --output ./recovery-key.age
    else
        say "5. admin recovery key: skipped (no --recipient); the operator generates it during 'finish'"
    fi

    say "6. posture before the first start"
    KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin validate --posture --config ./keyorix.yaml

    say "7. start the server"
    start_server bootstrap

    say "8. trust the certificate, create the first admin"
    ./bin/keyorix config set ca_file "$dir/certs/server.crt"
    KEYORIX_ADMIN_PASSWORD_FILE=secrets/admin_password KEYORIX_BOOTSTRAP_TOKEN_FILE=secrets/bootstrap_token ./bin/keyorix system init --server "https://localhost:$(port)" --admin-username admin --admin-email "$admin_email"

    cat <<EOF

== 9. OPERATOR STEP (run it yourself; this script and any assistant must not)
In a terminal of your own on this host:

  cd $dir
  ./bin/keyorix login --server https://localhost:$(port) --username admin < secrets/admin_password
  ./bin/keyorix mfa enroll        # add the printed secret to your authenticator app
  ./bin/keyorix mfa activate      # code from the app, then the password from secrets/admin_password

Move secrets/admin_password into your password manager, save the recovery codes
'mfa activate' prints, then delete the file (shred -u, or rm -P on macOS).
Then run:  $0 finish --dir $dir
EOF
    ;;
finish)
    cd "$dir" || die "no $dir"
    say "10. stop the server, drop the bootstrap token"
    stop_server
    rm -f secrets/bootstrap_token
    if [ ! -e recovery-key.age ] && [ -z "${KEYORIX_RECOVERY_KEY_DONE:-}" ]; then
        cat <<EOF

== OPERATOR STEP: no recovery key was encrypted to a recipient. While the server is
stopped, run this yourself, in your own terminal, and store the printed key offline:

  cd $dir
  KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml

Then run:  KEYORIX_RECOVERY_KEY_DONE=1 $0 finish --dir $dir
EOF
        exit 0
    fi
    say "11. proof: posture check"
    KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin validate --posture --config ./keyorix.yaml ||
        die "posture check failed (an admin-mfa deviation means step 9 is not done: '$0 start --dir $dir', enrol, then 'finish' again)"
    say "12. start the server"
    start_server
    cat <<EOF

Done. Back up keys/, keyorix.db and keyorix.yaml together, and secrets/master_password
SEPARATELY and offline: without it every stored secret is lost. Replace certs/server.crt
with a CA-issued certificate (same paths) before other machines connect.
EOF
    ;;
start) cd "$dir" || die "no $dir"; start_server ;;
stop) cd "$dir" || die "no $dir"; stop_server ;;
*) die "usage: $0 setup|finish|start|stop [options] (see --help)" ;;
esac
