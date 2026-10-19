#!/usr/bin/env bash
# scripts/drills/lib.sh -- shared helpers for the operational drills (PROD-OPS-1).
#
# Sourced by upgrade.sh, backup-restore.sh, key-rotation.sh and disaster.sh. Every
# drill runs REAL binaries (no mocks): a keyorix-server and a keyorix CLI, on either
# a SQLite file or a PostgreSQL database, in an isolated directory under
# $DRILL_ROOT. It needs no container engine, so it runs on a laptop, in CI or on a
# VM. (Run it inside a container too, if you want one: nothing here assumes the
# host.)
#
# Secrets never travel on a command line (ps shows argv): the master passphrase,
# admin password, bootstrap token and database password live in the environment or
# in 0600 files, and HTTP calls read their headers/bodies from files.
#
# Environment (all optional unless stated):
#   DRILL_SERVER_BIN   keyorix-server binary under test (default: build ./server)
#   DRILL_CLI_BIN      keyorix CLI binary (default: build ./cli)
#   DRILL_BACKEND      sqlite (default) | postgres
#   DRILL_PG_DSN_FILE  postgres only: file holding a postgres:// URL of an EMPTY
#                      database (read from a file so the password is never on argv)
#   DRILL_ROOT         work area (default: <repo>/.scratch/drills); each run makes a
#                      fresh sub-directory and removes it on success
#   DRILL_KEEP=1       keep the work area on success as well as on failure

set -euo pipefail

DRILL_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRILL_ROOT="${DRILL_ROOT:-$DRILL_REPO_ROOT/.scratch/drills}"
DRILL_BACKEND="${DRILL_BACKEND:-sqlite}"
DRILL_PORT_BASE="${DRILL_PORT_BASE:-18300}"

# Anything that was started or created is recorded here so the EXIT trap can clean up.
DRILL_PIDS=()
DRILL_DIR=""
DRILL_FAILED=1

fail() {
    echo "" >&2
    echo "DRILL FAILED: $1" >&2
    exit 1
}

step() { echo "==> $*"; }
ok() { echo "    ok: $*"; }

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

drill_cleanup() {
    local pid
    for pid in "${DRILL_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    if [ -n "$DRILL_DIR" ]; then
        if [ "$DRILL_FAILED" = "1" ] || [ "${DRILL_KEEP:-}" = "1" ]; then
            echo "    work area kept: $DRILL_DIR" >&2
        else
            rm -rf "$DRILL_DIR"
        fi
    fi
}

# drill_begin <name>: make the work area, set the per-run secrets, build binaries.
drill_begin() {
    local name="$1"
    command -v curl >/dev/null || fail "curl is required"
    command -v jq >/dev/null || fail "jq is required"
    mkdir -p "$DRILL_ROOT"
    DRILL_DIR="$(mktemp -d "$DRILL_ROOT/$name.XXXXXX")"
    trap drill_cleanup EXIT
    mkdir -p "$DRILL_DIR/bin"

    # One set of credentials per run; the same master passphrase is used by every
    # instance of the run, as an operator restoring a backup would use theirs.
    KEYORIX_MASTER_PASSWORD="drill-master-$(rand_hex 16)"
    export KEYORIX_MASTER_PASSWORD
    DRILL_ADMIN_PASSWORD="Drill-Op3rator-Passw0rd!-$(rand_hex 6)"
    DRILL_BOOTSTRAP_TOKEN="$(rand_hex 24)"

    if [ -n "${DRILL_SERVER_BIN:-}" ]; then
        [ -x "$DRILL_SERVER_BIN" ] || fail "DRILL_SERVER_BIN=$DRILL_SERVER_BIN is not executable"
    else
        step "building keyorix-server from $DRILL_REPO_ROOT"
        (cd "$DRILL_REPO_ROOT" && go build -o "$DRILL_DIR/bin/keyorix-server" ./server) || fail "server build failed"
        DRILL_SERVER_BIN="$DRILL_DIR/bin/keyorix-server"
    fi
    if [ -n "${DRILL_CLI_BIN:-}" ]; then
        [ -x "$DRILL_CLI_BIN" ] || fail "DRILL_CLI_BIN=$DRILL_CLI_BIN is not executable"
    else
        step "building keyorix CLI from $DRILL_REPO_ROOT/cli"
        (cd "$DRILL_REPO_ROOT/cli" && GOWORK=off go build -o "$DRILL_DIR/bin/keyorix" .) || fail "cli build failed"
        DRILL_CLI_BIN="$DRILL_DIR/bin/keyorix"
    fi
    (cd "$DRILL_REPO_ROOT" && GOWORK=off go build -o "$DRILL_DIR/bin/totpgen" scripts/totpgen/main.go) \
        || fail "totpgen build failed"
    echo "==> drill dir: $DRILL_DIR (backend: $DRILL_BACKEND)"
}

drill_end() {
    DRILL_FAILED=0
    echo ""
    echo "$1 PASSED"
}

# ---------------------------------------------------------------------------
# Instances. An instance is a directory holding keyorix.yaml, keys/, certs/,
# secrets/, the SQLite file (if any), a CLI HOME, the server log and pid file.
# All admin/server commands run with the instance directory as cwd: the config's
# key/db paths must be relative.
# ---------------------------------------------------------------------------

# pg_parse <dsn-file>: sets PG_USER PG_PASS PG_HOST PG_PORT PG_DB from a postgres:// URL.
pg_parse() {
    local url
    url="$(cat "$1")"
    if [[ "$url" =~ ^postgres(ql)?://([^:@/]+):([^@]*)@([^:/]+):([0-9]+)/([^?]+) ]]; then
        PG_USER="${BASH_REMATCH[2]}"; PG_PASS="${BASH_REMATCH[3]}"
        PG_HOST="${BASH_REMATCH[4]}"; PG_PORT="${BASH_REMATCH[5]}"; PG_DB="${BASH_REMATCH[6]}"
    else
        fail "cannot parse the postgres URL in $1 (want postgres://user:password@host:port/db)"
    fi
}

# inst_new <name> <port> [pgdsnfile]: init + encryption init + migrate with $DRILL_SERVER_BIN.
# Sets INST_<NAME-less> globals via inst_use afterwards.
inst_new() {
    local name="$1" port="$2" dsnfile="${3:-${DRILL_PG_DSN_FILE:-}}"
    local d="$DRILL_DIR/$name"
    mkdir -p "$d/home"
    (
        cd "$d"
        "$DRILL_SERVER_BIN" admin init --config ./keyorix.yaml >"$d/init.log" 2>&1 || { cat "$d/init.log" >&2; exit 1; }
        sed -i.bak -E "s/port: \"8080\"/port: \"$port\"/" keyorix.yaml
        rm -f keyorix.yaml.bak
    ) || fail "admin init failed for $name"
    if [ "$DRILL_BACKEND" = "postgres" ]; then
        [ -n "$dsnfile" ] || fail "DRILL_BACKEND=postgres needs DRILL_PG_DSN_FILE"
        pg_parse "$dsnfile"
        (
            cd "$d"
            sed -i.bak -E \
                -e 's/^  type: sqlite.*/  type: postgres/' \
                -e "s|^    path: \"keyorix.db\"|    host: \"$PG_HOST\"\n    port: \"$PG_PORT\"\n    name: \"$PG_DB\"\n    user: \"$PG_USER\"\n    ssl_mode: disable|" \
                keyorix.yaml
            rm -f keyorix.yaml.bak keyorix.db
        ) || fail "postgres config edit failed for $name"
    fi
    inst_admin "$name" encryption init >/dev/null || fail "admin encryption init failed for $name"
    inst_admin "$name" migrate >/dev/null || fail "admin migrate failed for $name"
}

# inst_env <name>: the environment a process of this instance runs with (printed as VAR=val words
# for use with `env`). The DB password for postgres is exported by the caller via inst_run.
inst_run() {
    # inst_run <name> <cmd...>: run a command in the instance dir with its environment.
    local name="$1"; shift
    local d="$DRILL_DIR/$name"
    (
        cd "$d"
        if [ "$DRILL_BACKEND" = "postgres" ]; then
            export KEYORIX_DB_PASSWORD="$PG_PASS"
        fi
        "$@"
    )
}

# inst_admin <name> [--server-bin X] <admin args...>: `keyorix-server admin ...` (server stopped).
inst_admin() {
    local name="$1"; shift
    local bin="${DRILL_ADMIN_BIN:-$DRILL_SERVER_BIN}"
    inst_run "$name" env KEYORIX_CONFIG_PATH=./keyorix.yaml "$bin" admin "$@" --config ./keyorix.yaml
}

# srv_start <name> <port> [server-bin]: start the server in the background, wait for /health.
srv_start() {
    local name="$1" port="$2" bin="${3:-$DRILL_SERVER_BIN}"
    local d="$DRILL_DIR/$name"
    [ -f "$d/server.pid" ] && fail "$name already has a server (pid file present)"
    (
        cd "$d"
        if [ "$DRILL_BACKEND" = "postgres" ]; then
            export KEYORIX_DB_PASSWORD="$PG_PASS"
        fi
        KEYORIX_CONFIG_PATH=./keyorix.yaml KEYORIX_BOOTSTRAP_TOKEN="$DRILL_BOOTSTRAP_TOKEN" \
            nohup "$bin" >>"$d/server.log" 2>&1 &
        echo $! >"$d/server.pid"
    )
    DRILL_PIDS+=("$(cat "$d/server.pid")")
    local i
    for i in $(seq 1 60); do
        if curl -fs --cacert "$d/certs/server.crt" "https://127.0.0.1:$port/health" >/dev/null 2>&1; then
            return 0
        fi
        kill -0 "$(cat "$d/server.pid")" 2>/dev/null || { tail -30 "$d/server.log" >&2; fail "$name server exited during start"; }
        sleep 0.5
    done
    tail -30 "$d/server.log" >&2
    fail "$name server never became healthy"
}

# srv_stop <name>: graceful stop (SIGTERM), wait for exit.
srv_stop() {
    local name="$1" d pid i
    d="$DRILL_DIR/$name"
    [ -f "$d/server.pid" ] || return 0
    pid="$(cat "$d/server.pid")"
    kill "$pid" 2>/dev/null || true
    for i in $(seq 1 60); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    kill -0 "$pid" 2>/dev/null && fail "$name server did not stop within 30s of SIGTERM"
    rm -f "$d/server.pid"
}

# srv_kill9 <name>
srv_kill9() {
    local name="$1" d
    d="$DRILL_DIR/$name"
    kill -9 "$(cat "$d/server.pid")" 2>/dev/null || true
    sleep 0.5
    rm -f "$d/server.pid"
}

# ---------------------------------------------------------------------------
# CLI and HTTP, per instance. The CLI keeps its session under HOME=<inst>/home.
# ---------------------------------------------------------------------------

inst_url() { echo "https://127.0.0.1:$2"; }

# cli <name> <port> <args...>
cli() {
    local name="$1" port="$2"; shift 2
    local d="$DRILL_DIR/$name"
    (
        cd "$d"
        HOME="$d/home" KEYORIX_CA_FILE="$d/certs/server.crt" KEYORIX_SERVER="https://127.0.0.1:$port" \
            KEYORIX_PASSWORD="${DRILL_CLI_PASSWORD:-$DRILL_ADMIN_PASSWORD}" \
            "${DRILL_CLI_OVERRIDE:-$DRILL_CLI_BIN}" "$@"
    )
}

# totp <secret> [offset-seconds]
totp() { "$DRILL_DIR/bin/totpgen" "$@"; }

# totp_fresh <secret>: a code that differs from the last one this run consumed FOR THAT SECRET
# (anti-replay is per account: two accounts alternating must not share one "last code").
totp_fresh() {
    local secret="$1" code i last lastfile
    # The last consumed code lives in a file per secret: callers use this inside $(...), a subshell.
    lastfile="$DRILL_DIR/.last-totp.$(printf '%s' "$secret" | cksum | cut -d' ' -f1)"
    for i in $(seq 1 40); do
        code="$(totp "$secret")"
        last="$(cat "$lastfile" 2>/dev/null || true)"
        if [ "$code" != "$last" ]; then
            printf '%s' "$code" >"$lastfile"
            echo "$code"
            return 0
        fi
        sleep 1
    done
    fail "could not get a fresh TOTP code"
}

# api <name> <port> <method> <path> [body-file]: authenticated call with the admin session token
# in <inst>/home (read from a header file, never argv). Prints the body; sets API_CODE.
api_bearer_file() { echo "$DRILL_DIR/$1/bearer.hdr"; }

# http_code <name> <port> <path> <hdrfile>
http_code() {
    local name="$1" port="$2" path="$3" hdr="${4:-}"
    local d="$DRILL_DIR/$name"
    if [ -n "$hdr" ]; then
        curl -s -o /dev/null -w '%{http_code}' --cacert "$d/certs/server.crt" -H @"$hdr" "https://127.0.0.1:$port$path"
    else
        curl -s -o /dev/null -w '%{http_code}' --cacert "$d/certs/server.crt" "https://127.0.0.1:$port$path"
    fi
}

http_body() {
    local name="$1" port="$2" path="$3" hdr="$4"
    curl -s --cacert "$DRILL_DIR/$name/certs/server.crt" -H @"$hdr" "https://127.0.0.1:$port$path"
}

write_bearer() { # <file> <token>
    (umask 077 && printf 'Authorization: Bearer %s\n' "$2" >"$1")
}

# ---------------------------------------------------------------------------
# Seeding: realistic data through the shipped CLI against a running server.
# After seed_data the globals SEED_* describe what a verifier must find.
# ---------------------------------------------------------------------------

SEED_MFA_SECRET=""
SEED_MACHINE_TOKEN_FILE=""

# seed_data <name> <port>
seed_data() {
    local name="$1" port="$2" d out
    d="$DRILL_DIR/$name"

    step "bootstrap admin ($name)"
    KEYORIX_ADMIN_PASSWORD="$DRILL_ADMIN_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$DRILL_BOOTSTRAP_TOKEN" \
        cli "$name" "$port" system init --server "https://127.0.0.1:$port" --admin-username admin \
        --admin-email admin@drill.local >/dev/null || fail "system init failed"
    cli "$name" "$port" login --server "https://127.0.0.1:$port" --username admin >/dev/null || fail "first login failed"

    step "MFA enrolment (require_mfa defaults on)"
    out="$(cli "$name" "$port" mfa enroll)" || fail "mfa enroll failed"
    SEED_MFA_SECRET="$(echo "$out" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
    [ -n "$SEED_MFA_SECRET" ] || fail "no MFA secret in mfa enroll output"
    (umask 077 && printf '%s' "$SEED_MFA_SECRET" >"$d/mfa.secret")
    KEYORIX_MFA_CODE="$(totp_fresh "$SEED_MFA_SECRET")" cli "$name" "$port" mfa activate >/dev/null || fail "mfa activate failed"
    login_admin "$name" "$port"

    step "projects, secrets, versions"
    cli "$name" "$port" project create --name payments >/dev/null || fail "project create payments"
    cli "$name" "$port" project create --name platform >/dev/null || fail "project create platform"
    local i
    for i in 1 2 3; do
        (umask 077 && printf 'seed-value-%s-v1-%s' "$i" "$(rand_hex 6)" >"$d/val.$i")
        cli "$name" "$port" secret create --name "seed-secret-$i" --from-file ./val.$i \
            --project 1 --environment 1 >/dev/null || fail "secret create $i"
    done
    # two more versions of secret 1 (the value a verifier must find is the LAST one)
    for i in 2 3; do
        (umask 077 && printf 'seed-value-1-v%s-%s' "$i" "$(rand_hex 6)" >"$d/val.1")
        cli "$name" "$port" secret update --id 1 --from-file ./val.1 >/dev/null || fail "secret update v$i"
    done
    cp "$d/val.1" "$d/expect.secret1"
    cp "$d/val.2" "$d/expect.secret2"
    cp "$d/val.3" "$d/expect.secret3"

    step "users, roles, share"
    cli "$name" "$port" user create --username alice --email alice@drill.local --one-time-password >/dev/null \
        || fail "user create alice"
    cli "$name" "$port" rbac assign-role --user admin@drill.local --role project_admin --project default >/dev/null \
        || fail "assign owner role"
    cli "$name" "$port" rbac assign-role --user alice@drill.local --role project_viewer --project default >/dev/null \
        || fail "assign recipient role"
    cli "$name" "$port" share create --secret-id 1 --recipient-id 2 --permission read >/dev/null || fail "share create"

    step "machine identity + token"
    cli "$name" "$port" machine create --name drill-ci --project default --type ci >/dev/null || fail "machine create"
    out="$(cli "$name" "$port" machine token issue drill-ci --name drill-token-1 --project default --expires-in-days 30)" \
        || fail "machine token issue"
    local tok
    tok="$(echo "$out" | grep '^Token:' | awk '{print $2}')"
    [ -n "$tok" ] || fail "no machine token in output"
    SEED_MACHINE_TOKEN_FILE="$d/bearer.machine.hdr"
    write_bearer "$SEED_MACHINE_TOKEN_FILE" "$tok"
    cli "$name" "$port" machine grant-role drill-ci --project default --role project_viewer >/dev/null || fail "machine grant-role"

    ok "seeded: 2 projects, 3 secrets (secret 1 has 3 versions), 2 users, 1 share, 1 machine identity+token"
}

# login_admin <name> <port>: log in with password + a fresh TOTP code (the MFA login path).
login_admin() {
    local name="$1" port="$2" secret
    secret="$(cat "$DRILL_DIR/$name/mfa.secret" 2>/dev/null || cat "$DRILL_DIR/${DRILL_MFA_FROM:-$name}/mfa.secret")"
    KEYORIX_MFA_CODE="$(totp_fresh "$secret")" cli "$name" "$port" login --server "https://127.0.0.1:$port" --username admin >/dev/null \
        || fail "MFA login failed on $name"
}

# verify_seed <name> <port>: assert the seeded data is intact and usable.
verify_seed() {
    local name="$1" port="$2" d out want
    d="$DRILL_DIR/$name"
    local src="${DRILL_SEED_DIR:-$name}"
    login_admin "$name" "$port"
    ok "admin MFA login"
    local i
    for i in 1 2 3; do
        out="$(cli "$name" "$port" secret get --id "$i" --show-value)" || fail "secret get $i failed"
        want="$(cat "$DRILL_DIR/$src/expect.secret$i")"
        grep -qF "$want" <<<"$out" || fail "secret $i does not decrypt to the seeded value (want $want)"
    done
    ok "3 secrets decrypt to the seeded values (secret 1 at its latest version)"
    out="$(cli "$name" "$port" secret versions --id 1)" || fail "secret versions failed"
    [ "$(echo "$out" | grep -cE '^[[:space:]]*[0-9]+[[:space:]]')" -ge 3 ] || fail "secret 1 lost versions:
$out"
    ok "secret 1 still has its 3 versions"
    out="$(cli "$name" "$port" share list --secret-id 1)" || fail "share list failed"
    grep -qE '^1[[:space:]]+1[[:space:]]+1[[:space:]]+2[[:space:]]' <<<"$out" || fail "share to alice is gone:
$out"
    ok "share intact"
    out="$(http_body "$name" "$port" "/api/v1/secrets/1?include_value=true" "$DRILL_DIR/$src/bearer.machine.hdr")"
    grep -qF "$(cat "$DRILL_DIR/$src/expect.secret1")" <<<"$out" || fail "machine token no longer reads secret 1: $out"
    ok "machine token still authenticates and reads"
}

# verify_audit <name> [extra args]: offline verify-audit with the server stopped; must say VALID.
verify_audit() {
    local name="$1"; shift
    local out
    out="$(inst_admin "$name" verify-audit "$@" 2>&1)" || fail "verify-audit exited non-zero on $name:
$out"
    grep -qE '^Verdict: VALID$' <<<"$out" || fail "verify-audit did not report Verdict: VALID on $name:
$out"
    AUDIT_COUNT="$(echo "$out" | awk '/chained events:/ {print $3}')"
    ok "verify-audit VALID ($name, ${AUDIT_COUNT:-?} chained events)"
}

# free_port <index>: deterministic, per-run-index port.
drill_port() { echo $((DRILL_PORT_BASE + $1)); }
