#!/usr/bin/env bash
# Seeds a throwaway HashiCorp Vault (or OpenBao) container to look like 3 years of
# real-world neglect, for MIG-1's migration-fidelity harness
# (docs/specs/vault-migration-fidelity.md). Local Docker only -- no pve01, no real
# customer data.
#
# Usage:
#   BACKEND=vault|openbao SEED_SIZE=<n> ./seed.sh <env-out-file>
#
# SEED_SIZE is the number of BULK KV v2 secrets created under secret/bulk/ (on top
# of the fixed, hand-described fixture below, which always exists regardless of
# SEED_SIZE). Default 30 (fast, PR-CI-sized smoke test); the nightly job sets
# SEED_SIZE=5000. <env-out-file> receives shell-sourceable VAULT_ADDR/VAULT_TOKEN/
# container-name vars for the next stage (migrate.sh / diff.sh) to consume.
set -euo pipefail

BACKEND="${BACKEND:-vault}"
SEED_SIZE="${SEED_SIZE:-30}"
ENV_OUT="${1:?usage: seed.sh <env-out-file>}"

case "$BACKEND" in
  vault)
    IMAGE="hashicorp/vault@sha256:0450896c43b13879b19442b204ce29dd19b5a10fce43d5cf38af17da20f56f4d" # 1.15, pinned -- matches scripts/e2e/journeys journey4 and ci.yml's migrate job
    ROOT_TOKEN_VAR="VAULT_DEV_ROOT_TOKEN_ID"
    LISTEN_VAR="VAULT_DEV_LISTEN_ADDRESS"
    ;;
  openbao)
    IMAGE="openbao/openbao@sha256:05d777d6b47d0d0985b87317914632de31d98994b58e490ebabde3c389b09f8f" # 2.0, pinned -- same digest journey4/ci.yml use
    ROOT_TOKEN_VAR="BAO_DEV_ROOT_TOKEN_ID"
    LISTEN_VAR="BAO_DEV_LISTEN_ADDRESS"
    ;;
  *)
    echo "BACKEND must be vault or openbao, got: $BACKEND" >&2; exit 1 ;;
esac

ROOT_TOKEN="mig1-root-token"
NAME="mig1-${BACKEND}-$$"

echo "▶ starting ${BACKEND} (${NAME})"
docker run -d --rm --name "$NAME" --cap-add=IPC_LOCK -p 127.0.0.1:0:8200 \
  -e "${ROOT_TOKEN_VAR}=${ROOT_TOKEN}" -e "${LISTEN_VAR}=0.0.0.0:8200" \
  "$IMAGE" >/dev/null

HOST_PORT="$(docker port "$NAME" 8200/tcp | grep 127.0.0.1 | head -1 | cut -d: -f2)"
ADDR="http://127.0.0.1:${HOST_PORT}"

for _ in $(seq 1 30); do curl -sf "${ADDR}/v1/sys/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "${ADDR}/v1/sys/health" >/dev/null 2>&1 || { echo "${BACKEND} never became healthy"; docker logs "$NAME"; exit 1; }
echo "✓ ${BACKEND} healthy at ${ADDR}"

H=(-H "X-Vault-Token: ${ROOT_TOKEN}")

urlencode_path() { # percent-encodes each "/"-separated segment, preserving the separators --
  # split, encode and re-join in jq so no IFS juggling is needed (and the shell's
  # field splitting is never altered).
  jq -rn --arg p "$1" '$p | split("/") | map(@uri) | join("/")'
}

req() { # method path json-body-or-empty -- path segments are percent-encoded (unicode/spaces in
        # Vault paths and keys are part of this fixture's own coverage, so the seed script
        # itself must send a well-formed request, not rely on curl to guess).
  local method="$1" path body
  path="$(urlencode_path "$2")"
  body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sf "${H[@]}" -X "$method" "${ADDR}/v1/${path}" -d "$body"
  else
    curl -sf "${H[@]}" -X "$method" "${ADDR}/v1/${path}"
  fi
}

echo "▶ mounts: kv v1 'kv1-legacy', kv v2 'team-b' (secret/ kv2 is the dev-mode default)"
req POST "sys/mounts/kv1-legacy" '{"type":"kv","options":{"version":"1"}}' >/dev/null
req POST "sys/mounts/team-b" '{"type":"kv","options":{"version":"2"}}' >/dev/null

echo "▶ nested paths (6+ deep), unicode and spaces"
req POST "secret/data/org/team-a/service/payments/db primary/café crédentials" \
  '{"data":{"密码":"mig1-deep-unicode-pw-7a21","user name":"payments-svc"}}' >/dev/null
req POST "secret/data/org/team-a/service/payments/db primary/naive" \
  '{"data":{"value":"mig1-naive-pw-55bb"}}' >/dev/null

echo "▶ many versions, one soft-deleted NON-latest version (secret/data/versioned/rotating-key)"
# Ends on a LIVE version 5, deliberately -- a destroyed/soft-deleted version 2 shadowed by a
# live version 5 must still import v5's value normally. The two dedicated fixtures below
# (soft-deleted-latest / destroyed-latest) are what exercise "the LATEST version itself is
# gone", kept structurally separate so one fixture never means two different things.
for v in 1 2 3 4 5; do
  req POST "secret/data/versioned/rotating-key" "{\"data\":{\"value\":\"mig1-rotating-v${v}\"}}" >/dev/null
done
req POST "secret/delete/versioned/rotating-key" '{"versions":[2]}' >/dev/null   # soft-deleted, non-latest -- v5 still imports live

echo "▶ latest-version soft-deleted and destroyed leaves (must show up as explicit skips)"
req POST "secret/data/versioned/soft-deleted-latest" '{"data":{"value":"mig1-will-be-soft-deleted"}}' >/dev/null
req POST "secret/delete/versioned/soft-deleted-latest" '{"versions":[1]}' >/dev/null
req POST "secret/data/versioned/destroyed-latest" '{"data":{"value":"mig1-will-be-destroyed"}}' >/dev/null
req POST "secret/destroy/versioned/destroyed-latest" '{"versions":[1]}' >/dev/null

echo "▶ custom_metadata, max_versions, cas_required"
req POST "secret/metadata/versioned/rotating-key" \
  '{"custom_metadata":{"owner":"payments-team","ticket":"MIG-1"},"max_versions":10,"cas_required":true}' >/dev/null

echo "▶ value edge cases: empty, large (near Keyorix's actual limit), oversized, binary/base64, JSON blob, multi-line PEM"
req POST "secret/data/values/empty-value" '{"data":{"value":""}}' >/dev/null
# Keyorix's default secrets.limits.max_secret_size is 64 KiB (internal/config.DefaultMaxSecretSize) --
# Vault itself imposes no comparable per-value limit, so a "near the size limit" fixture must be
# sized relative to the TARGET's limit, not an arbitrary large number, to actually test this
# dimension rather than a different one. ~60KB is comfortably under 64KiB (survives);
# ~100KB (OVERSIZED_VALUE below) is comfortably over it (does not) -- both are real, deliberately
# distinct cases, not the same fixture at two sizes.
LARGE_VALUE="$(head -c 45000 /dev/urandom | base64 | tr -d '\n')" # ~60KB, under the 64KiB default limit
req POST "secret/data/values/large-value" "{\"data\":{\"value\":\"${LARGE_VALUE}\"}}" >/dev/null
OVERSIZED_VALUE="$(head -c 75000 /dev/urandom | base64 | tr -d '\n')" # ~100KB, over the 64KiB default limit but under Vault's own 10MB response cap
req POST "secret/data/values/oversized-value" "{\"data\":{\"value\":\"${OVERSIZED_VALUE}\"}}" >/dev/null
BINARY_B64="$(head -c 4096 /dev/urandom | base64 | tr -d '\n')"
req POST "secret/data/values/binary-value" "{\"data\":{\"value\":\"${BINARY_B64}\"}}" >/dev/null
req POST "secret/data/values/json-blob" '{"data":{"value":"{\"nested\":{\"array\":[1,2,3],\"flag\":true}}"}}' >/dev/null
PEM_VALUE='-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...mig1-fake-pem-not-a-real-key...\n-----END RSA PRIVATE KEY-----'
req POST "secret/data/values/pem-key" "{\"data\":{\"value\":\"${PEM_VALUE}\"}}" >/dev/null

echo "▶ kv v1 mount (secret/-style leaves, no version concept) and second kv2 mount"
req POST "kv1-legacy/legacy/db-password" '{"value":"mig1-kv1-legacy-pw-91cc"}' >/dev/null
req POST "team-b/data/standalone-secret" '{"data":{"value":"mig1-team-b-value-44dd"}}' >/dev/null

echo "▶ policies: deny, globbing, templated"
req PUT "sys/policies/acl/mig1-deny-prod" \
  '{"policy":"path \"secret/data/org/team-a/*\" { capabilities = [\"deny\"] }"}' >/dev/null
req PUT "sys/policies/acl/mig1-glob-readonly" \
  '{"policy":"path \"secret/data/*\" { capabilities = [\"read\",\"list\"] }"}' >/dev/null
req PUT "sys/policies/acl/mig1-templated" \
  '{"policy":"path \"secret/data/users/{{identity.entity.id}}/*\" { capabilities = [\"read\"] }"}' >/dev/null

echo "▶ auth methods: AppRole, userpass, Kubernetes"
req POST "sys/auth/approle" '{"type":"approle"}' >/dev/null
req POST "auth/approle/role/mig1-migrator" '{"token_policies":"mig1-glob-readonly","token_ttl":"10m"}' >/dev/null
req POST "sys/auth/userpass" '{"type":"userpass"}' >/dev/null
req POST "auth/userpass/users/mig1-operator" '{"password":"mig1-userpass-pw","policies":"mig1-glob-readonly"}' >/dev/null
req POST "sys/auth/kubernetes" '{"type":"kubernetes"}' >/dev/null
# Dev-mode has no real cluster to verify against. Vault's config endpoint defaults
# kubernetes_ca_cert/token_reviewer_jwt to reading the in-cluster service-account files
# when omitted -- absent here (this container isn't a k8s pod), which makes the plain
# "just a host" config 400. Supplying placeholder-but-well-formed values for both skips
# that local-file read; neither is validated against a real cluster at config time, only
# on an actual login attempt, which this seed never makes.
MIG1_FAKE_JWT="$(printf 'h.%s.s' "$(head -c 32 /dev/urandom | base64 | tr -d '\n=+/')")"
MIG1_FAKE_CA_CERT='-----BEGIN CERTIFICATE-----\nMIIBhTCCASugAwIBAgIUmig1fakecertnotreal0wCgYIKoZIzj0EAwIwEjEQMA4G\nA1UEAxMHbWlnMS1jYTAeFw0yNjA5MjUwMDAwMDBaFw0zNjA5MjMwMDAwMDBaMBIx\nEDAOBgNVBAMTB21pZzEtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATN3+ma\nmig1fakecertfixturenotarealcertificatevalueusedonlyforseeddata\n-----END CERTIFICATE-----'
req POST "auth/kubernetes/config" \
  "{\"kubernetes_host\":\"https://10.96.0.1:443\",\"kubernetes_ca_cert\":\"${MIG1_FAKE_CA_CERT}\",\"token_reviewer_jwt\":\"${MIG1_FAKE_JWT}\"}" >/dev/null
req POST "auth/kubernetes/role/mig1-k8s-role" \
  '{"bound_service_account_names":"*","bound_service_account_namespaces":"default","token_policies":"mig1-glob-readonly"}' >/dev/null

echo "▶ a plain token bound to a policy (never a root token for ordinary use)"
req POST "auth/token/create" '{"policies":["mig1-glob-readonly"],"ttl":"1h","display_name":"mig1-issued-token"}' >/dev/null

echo "▶ audit device"
req PUT "sys/audit/mig1-file-audit" '{"type":"file","options":{"file_path":"stdout"}}' >/dev/null

echo "▶ bulk KV v2 secrets under secret/bulk/ (count=${SEED_SIZE}, for pagination/perf coverage)"
seq 1 "$SEED_SIZE" | xargs -P 8 -I{} bash -c '
  curl -sf -H "X-Vault-Token: '"${ROOT_TOKEN}"'" -X POST \
    "'"${ADDR}"'/v1/secret/data/bulk/secret-{}" \
    -d "{\"data\":{\"value\":\"mig1-bulk-value-{}\"}}" >/dev/null
'
echo "✓ seeded ${SEED_SIZE} bulk secrets"

{
  echo "export MIG1_BACKEND=${BACKEND}"
  echo "export MIG1_CONTAINER=${NAME}"
  echo "export VAULT_ADDR=${ADDR}"
  echo "export VAULT_TOKEN=${ROOT_TOKEN}"
  echo "export MIG1_SEED_SIZE=${SEED_SIZE}"
} > "$ENV_OUT"

echo "✓ seed complete — env written to ${ENV_OUT}"
echo "  stop with: docker stop ${NAME}"
