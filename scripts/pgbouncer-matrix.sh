#!/usr/bin/env bash
# pgbouncer-matrix.sh — run the storage layer's PgBouncer slice
# (internal/storage/pgbouncer_postgres_test.go,
# internal/serverguard/serverguard_pooler_test.go) through PgBouncer in each
# supported pool mode (docs/postgresql-poolers.md):
#
#   session       pool_mode=session
#   tx-noprep     pool_mode=transaction, max_prepared_statements=0
#   tx-prep       pool_mode=transaction, max_prepared_statements=200 (PgBouncer >= 1.21)
#
# Needs Docker and Go. Starts one PostgreSQL and three PgBouncer containers on
# a private network, runs the tests once per mode, and removes everything it
# started on exit. Every name carries PGB_PREFIX so parallel runs on a shared
# host do not collide.
#
#   scripts/pgbouncer-matrix.sh                 # pooler matching each mode
#   PGB_POOLER=none scripts/pgbouncer-matrix.sh # what an undeclared pooler does
#
# Environment: PGB_PREFIX (default pgbmatrix), PGB_PORT_BASE (default 56430),
# PGB_PG_IMAGE (default postgres:16-alpine), PGB_IMAGE (default
# edoburu/pgbouncer:v1.24.1-p1), PGB_POOLER (default: per mode), PGB_RUN (go
# test -run pattern, default TestPgBouncer).
set -euo pipefail

prefix="${PGB_PREFIX:-pgbmatrix}"
base="${PGB_PORT_BASE:-56430}"
pg_image="${PGB_PG_IMAGE:-postgres:16-alpine}"
bouncer_image="${PGB_IMAGE:-edoburu/pgbouncer:v1.24.1-p1}"
run="${PGB_RUN:-TestPgBouncer}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
# A throwaway password for a container that lives as long as this script; it
# is never printed.
pw="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	for m in session tx-noprep tx-prep; do docker rm -f "${prefix}-${m}" >/dev/null 2>&1 || true; done
	docker rm -f "${prefix}-pg" >/dev/null 2>&1 || true
	docker network rm "${prefix}-net" >/dev/null 2>&1 || true
	rm -rf "${work}"
}
trap cleanup EXIT

docker network create "${prefix}-net" >/dev/null
# --env-file, not `-e POSTGRES_PASSWORD=...`: an argv is visible in ps (SCRIPTS-SECRETS-2).
( umask 077; printf 'POSTGRES_PASSWORD=%s\n' "${pw}" >"${work}/pg.env" )
docker run -d --name "${prefix}-pg" --network "${prefix}-net" -p "127.0.0.1:${base}:5432" \
	--env-file "${work}/pg.env" "${pg_image}" >/dev/null
rm -f "${work}/pg.env"
until docker exec "${prefix}-pg" pg_isready -U postgres -q; do sleep 1; done

start_bouncer() { # name port pool_mode max_prepared_statements
	local dir="${work}/$1"
	mkdir -p "${dir}"
	cat >"${dir}/pgbouncer.ini" <<EOF
[databases]
* = host=${prefix}-pg port=5432 user=postgres password=${pw}
[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = trust
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = $3
max_prepared_statements = $4
default_pool_size = 20
max_client_conn = 500
server_reset_query = DISCARD ALL
EOF
	echo '"postgres" ""' >"${dir}/userlist.txt"
	chmod 0644 "${dir}/pgbouncer.ini" "${dir}/userlist.txt"
	docker run -d --name "${prefix}-$1" --network "${prefix}-net" -p "127.0.0.1:$2:6432" \
		-v "${dir}:/etc/pgbouncer:ro" "${bouncer_image}" >/dev/null
}
start_bouncer session $((base + 1)) session 0
start_bouncer tx-noprep $((base + 2)) transaction 0
start_bouncer tx-prep $((base + 3)) transaction 200
sleep 2

direct="postgres://postgres:${pw}@127.0.0.1:${base}/postgres?sslmode=disable"
status=0
for spec in "session $((base + 1)) session" "tx-noprep $((base + 2)) transaction" "tx-prep $((base + 3)) transaction"; do
	read -r name port mode <<<"${spec}"
	echo "=== ${name} (pool_mode=${mode}, pooler=${PGB_POOLER:-pgbouncer-${mode}})"
	if ! (cd "${repo}" && KEYORIX_TEST_PG_DSN="${direct}" \
		KEYORIX_TEST_PGBOUNCER_DSN="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable" \
		KEYORIX_TEST_PGBOUNCER_POOL_MODE="${mode}" KEYORIX_TEST_PGBOUNCER_POOLER="${PGB_POOLER:-}" \
		go test ./internal/storage ./internal/serverguard -run "${run}" -count=1 -v 2>&1 |
		grep -E '^(=== RUN|\s*--- (PASS|FAIL|SKIP)|PASS$|FAIL|ok )|Error:|Messages:|_test.go:[0-9]+:|(ERROR|failed to)'); then
		status=1
	fi
done
exit "${status}"
