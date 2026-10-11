#!/usr/bin/env bash
# scripts/k8s-e2e/run.sh -- end-to-end proof that the three Kubernetes secret-
# delivery paths this repo ships (Helm chart, operator, keyorix-k8s-sync agent)
# plus the ESO webhook integration actually work against a real cluster, not
# just render correctly. Written after Session J (2026-09-28) found four real
# bugs that only a real cluster surfaced: a chart that renders and deploys
# fine but never completes admin bootstrap (PR #2271), an operator/k8s-sync
# doc gap on default scope + wipe-on-revocation (PR #2278), a k8s-sync
# Server-Side-Apply pruning defect that no unit test could catch since it's a
# fact about how a real apiserver processes SSA (PR #2286), and three
# manifest/doc bugs that break the documented ESO webhook install out of the
# box (PR #2289) -- `helm lint` + `helm template` + `kubeconform` (see `make
# k8s-hardening-check` in this same directory's sibling checks) catch none of
# these; only driving the real objects on a real API server does.
#
# MANUAL target only (not run in CI by default -- a nightly scheduled workflow
# running this was proposed but not added, since it's outside this session's
# owned paths (.github/workflows/**) -- see `make k8s-e2e`. Needs Docker + a
# kind cluster and takes several minutes, dominated by image builds and
# waiting out real reconcile intervals.
#
# Flow (each phase is independently idempotent -- delete-then-recreate its own
# namespace(s) at the top of the phase, not just at cleanup):
#   0. Preflight: docker/kind/helm/kubectl present, Docker daemon reachable.
#   1. Create (or reuse) a kind cluster; build the 4 images this repo publishes
#      for Kubernetes (server, web, operator, k8s-sync) and load them in.
#   2. J1 -- helm install the main chart (bundled Postgres), using ONLY the
#      README's documented required values; wait Ready; `helm test`; bootstrap
#      + a real secret round-trip via the CLI through a port-forward.
#   3. J2 -- static hardening: `helm lint` + `helm template` + `kubeconform` on
#      all 3 charts (default values and the airgap image tag); live check that
#      the rendered NetworkPolicies actually exist against the J2 install.
#   4. Set up a throwaway self-signed HTTPS front for the J1 server -- the
#      operator's `spec.server` validation and this agent's `keyorix_url`
#      validation both hard-require https (`http` only for `localhost`), and
#      neither chart exposes a way to inject a private CA (a real gap, noted
#      in Session J's report -- not fixed here, out of scope for an e2e
#      script). ESO's caProvider is the one integration that supports this
#      properly; the operator/agent get the same `SSL_CERT_FILE` +
#      `kubectl patch` workaround Session J used manually.
#   5. J3 -- install the operator (namespace-scoped default, per ADR-076),
#      create a least-privilege machine identity + KeyorixSecret CR, verify
#      Ready=True and the target Secret's value.
#   6. J4 -- install the k8s-sync agent, verify a mapped Secret syncs AND that
#      removing a mapping actually prunes the key (the exact regression this
#      session's PR #2286 fixes -- kept here as an ongoing real-cluster check,
#      not just the PR's own unit tests).
#   7. J5 -- install a real External Secrets Operator, apply the fixed
#      ClusterSecretStore + ExternalSecret from deploy/eso/, verify sync.
#   8. Clean up every namespace/release this script created. The kind cluster
#      itself is left running (fast re-runs) unless KEYORIX_K8S_E2E_KEEP_CLUSTER=0.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "" >&2
    echo "K8S E2E FAILED: $1" >&2
    exit 1
}

log() { echo "==> $1"; }

# --- 0. preflight ---
for bin in docker kind helm kubectl openssl go; do
    command -v "$bin" >/dev/null 2>&1 || fail "$bin is required and not on PATH"
done
docker info >/dev/null 2>&1 || fail "Docker daemon not reachable (docker info failed)"

CLUSTER_NAME="${KEYORIX_K8S_E2E_CLUSTER:-keyorix-k8s-e2e}"
KEEP_CLUSTER="${KEYORIX_K8S_E2E_KEEP_CLUSTER:-1}"
IMAGE_TAG="${KEYORIX_K8S_E2E_IMAGE_TAG:-k8s-e2e}"
NS_PREFIX="kxe2e"
WORK_DIR="$(mktemp -d)"
PORT_FORWARD_PIDS=()

cleanup() {
    log "Cleaning up namespaces/releases/port-forwards this run created"
    for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
    for ns in "${NS_PREFIX}-j1" "${NS_PREFIX}-j2" "${NS_PREFIX}-j3" "${NS_PREFIX}-j3-target" "${NS_PREFIX}-j4" "${NS_PREFIX}-j5" "${NS_PREFIX}-j5-target" "${NS_PREFIX}-eso"; do
        kubectl delete namespace "$ns" --wait=false --ignore-not-found >/dev/null 2>&1 || true
    done
    rm -rf "$WORK_DIR"
    if [ "$KEEP_CLUSTER" = "0" ]; then
        log "KEYORIX_K8S_E2E_KEEP_CLUSTER=0 -- deleting kind cluster $CLUSTER_NAME"
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Work dir: $WORK_DIR"

# --- 1. cluster + images ---
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "Reusing existing kind cluster $CLUSTER_NAME"
else
    log "Creating kind cluster $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 120s
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

log "Building images (tag :$IMAGE_TAG) -- server, web, operator, k8s-sync"
docker build -q -t "keyorix-server:${IMAGE_TAG}" -f "$REPO_ROOT/server/Dockerfile" "$REPO_ROOT" >/dev/null
docker build -q -t "keyorix-web:${IMAGE_TAG}" -f "$REPO_ROOT/web/Dockerfile" "$REPO_ROOT/web" >/dev/null
docker build -q -t "keyorix-operator:${IMAGE_TAG}" -f "$REPO_ROOT/operator/Dockerfile" "$REPO_ROOT/operator" >/dev/null
docker build -q -t "keyorix-k8s-sync:${IMAGE_TAG}" -f "$REPO_ROOT/cmd/keyorix-k8s-sync/Dockerfile" "$REPO_ROOT" >/dev/null

log "Loading images into $CLUSTER_NAME"
kind load docker-image "keyorix-server:${IMAGE_TAG}" "keyorix-web:${IMAGE_TAG}" \
    "keyorix-operator:${IMAGE_TAG}" "keyorix-k8s-sync:${IMAGE_TAG}" --name "$CLUSTER_NAME" >/dev/null

log "Building the thin CLI"
CLI_BIN="$WORK_DIR/keyorix"
(cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$CLI_BIN" .)
CLI_HOME="$WORK_DIR/cli-home"
mkdir -p "$CLI_HOME"
kx() { HOME="$CLI_HOME" "$CLI_BIN" "$@"; }

# Compliant with the server's admin-bootstrap password policy (>=16 chars,
# upper+lower+digit+special) AND avoids the default admin username as a
# substring -- both documented pitfalls found live in Session J (PR #2271).
ADMIN_PASSWORD='K8sE2e-Run-Passw0rd!'
DB_PASSWORD='k8s-e2e-db-password'
MASTER_PASSWORD='k8s-e2e-master-password'

port_forward() {
    # port_forward <namespace> <svc/name> <local-port>:<remote-port>
    # Registers the PID in PORT_FORWARD_PIDS (killed by cleanup on exit) --
    # run as a plain statement, NOT via $(...), since command substitution
    # would run this in a subshell and lose the array append.
    kubectl -n "$1" port-forward "$2" "$3" >/dev/null 2>&1 &
    local pid=$!
    PORT_FORWARD_PIDS+=("$pid")
    for _ in $(seq 1 30); do
        (exec 3<>"/dev/tcp/127.0.0.1/${3%%:*}") 2>/dev/null && exec 3>&- && return 0
        sleep 1
    done
    fail "port-forward $2 in $1 never became reachable"
}

# ============================================================================
# J1 -- helm install (bundled Postgres), README-documented values only,
# bootstrap + CLI secret round-trip.
# ============================================================================
J1_NS="${NS_PREFIX}-j1"
log "J1: helm install (bundled Postgres) in $J1_NS"
kubectl delete namespace "$J1_NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
helm install keyorix "$REPO_ROOT/deploy/helm/keyorix" -n "$J1_NS" --create-namespace \
    --set auth.masterPassword="$MASTER_PASSWORD" \
    --set postgresql.auth.password="$DB_PASSWORD" \
    --set auth.adminPassword="$ADMIN_PASSWORD" \
    --set server.image.repository=keyorix-server --set server.image.tag="$IMAGE_TAG" \
    --set web.image.repository=keyorix-web --set web.image.tag="$IMAGE_TAG" \
    --wait --timeout 180s

log "J1: helm test"
helm test keyorix -n "$J1_NS" >/dev/null

log "J1: verifying admin bootstrap actually completed (not just that the pod is Ready)"
kubectl -n "$J1_NS" logs deploy/keyorix-keyorix-server | grep -q "System initialised successfully\|already_initialized" \
    || kubectl -n "$J1_NS" logs deploy/keyorix-keyorix-server | grep -q '"POST http://localhost:8080/system/init HTTP/1.1" from \[::1\][^-]*- 200' \
    || fail "server logs show no successful POST /system/init -- admin bootstrap did not complete"

# Kept open for the rest of the script (J3/J4/J5 all issue machine tokens and
# create secrets through this same CLI session) -- registered in
# PORT_FORWARD_PIDS, killed once by cleanup() on exit, not per-use.
port_forward "$J1_NS" svc/keyorix-keyorix-web 18080:80
kx login --server http://localhost:18080 --username admin --password "$ADMIN_PASSWORD" >/dev/null \
    || fail "CLI login as bootstrapped admin failed"

# ADR-112 item 1: security.require_mfa defaults on, so the bootstrap admin is
# confined to the enrolment endpoints (EnforceAccountSetup) until it enrols
# -- every other authenticated call below would otherwise fail closed with
# "This deployment requires multi-factor authentication." Enrol for real
# (see scripts/smoke.sh's identical block for the full rationale), then log
# in again since ActivateMFA invalidates the pre-enrolment session.
log "J1: mfa enroll"
ENROLL_OUT="$(kx mfa enroll)" || fail "CLI mfa enroll failed"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse MFA secret from:
$ENROLL_OUT"

log "J1: mfa activate"
MFA_CODE="$(cd "$REPO_ROOT" && GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET")" \
    || fail "totpgen failed"
kx mfa activate --code "$MFA_CODE" --password "$ADMIN_PASSWORD" >/dev/null \
    || fail "CLI mfa activate failed"

log "J1: login (again, now MFA-enabled)"
MFA_LOGIN_CODE="$(cd "$REPO_ROOT" && GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET" 30)" \
    || fail "totpgen failed"
kx login --server http://localhost:18080 --username admin --password "$ADMIN_PASSWORD" \
    --mfa-code "$MFA_LOGIN_CODE" >/dev/null || fail "CLI login (MFA-enabled) failed"

kx secret create --name k8s-e2e-roundtrip --value 'k8s-e2e-roundtrip-value' --project 1 --environment 1 >/dev/null \
    || fail "CLI secret create failed"
GOT_VALUE="$(kx secret get --id 1 --show-value | awk '/^Decrypted Value/{getline; getline; print}')"
[ "$GOT_VALUE" = "k8s-e2e-roundtrip-value" ] || fail "secret round-trip mismatch: got '$GOT_VALUE'"
log "J1: secret round-trip OK"

BOOTSTRAP_TOKEN="$(kubectl -n "$J1_NS" get secret keyorix-keyorix -o jsonpath='{.data.KEYORIX_BOOTSTRAP_TOKEN}' | base64 -d)"
[ -n "$BOOTSTRAP_TOKEN" ] || fail "KEYORIX_BOOTSTRAP_TOKEN missing from the chart Secret"

# ============================================================================
# J2 -- static hardening (helm lint / template / kubeconform on all 3 charts)
# plus a live check that J1's NetworkPolicies actually exist.
# ============================================================================
log "J2: helm lint (all 3 charts)"
helm lint "$REPO_ROOT/deploy/helm/keyorix" >/dev/null
helm lint "$REPO_ROOT/deploy/helm/keyorix-operator" >/dev/null
helm lint "$REPO_ROOT/deploy/helm/keyorix-k8s-sync" >/dev/null

if command -v kubeconform >/dev/null 2>&1; then
    log "J2: kubeconform (default values + airgap image tag)"
    helm template keyorix "$REPO_ROOT/deploy/helm/keyorix" \
        --set auth.masterPassword=x --set postgresql.auth.password=x --set auth.adminPassword="$ADMIN_PASSWORD" \
        >"$WORK_DIR/rendered-default.yaml"
    kubeconform -strict -summary "$WORK_DIR/rendered-default.yaml" || fail "kubeconform failed on default-values render"
    helm template keyorix "$REPO_ROOT/deploy/helm/keyorix" \
        --set auth.masterPassword=x --set postgresql.auth.password=x --set auth.adminPassword="$ADMIN_PASSWORD" \
        --set server.image.tag="$(helm show chart "$REPO_ROOT/deploy/helm/keyorix" | awk '/^appVersion:/{print $2}' | tr -d '"')-airgap" \
        >"$WORK_DIR/rendered-airgap.yaml"
    kubeconform -strict -summary "$WORK_DIR/rendered-airgap.yaml" || fail "kubeconform failed on airgap-tag render"
else
    log "J2: kubeconform not installed -- skipping (helm lint above still ran)"
fi

log "J2: confirming the documented NetworkPolicies actually exist on the J1 install"
for np in keyorix-keyorix-server keyorix-keyorix-web keyorix-keyorix-postgresql; do
    kubectl -n "$J1_NS" get networkpolicy "$np" >/dev/null 2>&1 || fail "NetworkPolicy $np missing from the J1 install"
done

# ============================================================================
# TLS front for the J1 server -- operator/agent both hard-require https.
# ============================================================================
log "Setting up a throwaway self-signed HTTPS front for the J1 server"
TLS_HOST="keyorix-tls.${J1_NS}.svc.cluster.local"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK_DIR/tls.key" -out "$WORK_DIR/tls.crt" -days 1 \
    -subj "/CN=${TLS_HOST}" -addext "subjectAltName=DNS:${TLS_HOST}" >/dev/null 2>&1
kubectl -n "$J1_NS" create secret tls keyorix-tls-cert --cert="$WORK_DIR/tls.crt" --key="$WORK_DIR/tls.key" >/dev/null
cat >"$WORK_DIR/tls-proxy.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata: { name: keyorix-tls-nginx-conf, namespace: ${J1_NS} }
data:
  nginx.conf: |
    events {}
    http {
      server {
        listen 443 ssl;
        ssl_certificate /certs/tls.crt;
        ssl_certificate_key /certs/tls.key;
        location / { proxy_pass http://keyorix-keyorix-web:80; proxy_set_header Host \$host; }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: keyorix-tls, namespace: ${J1_NS} }
spec:
  replicas: 1
  selector: { matchLabels: { app: keyorix-tls } }
  template:
    metadata: { labels: { app: keyorix-tls } }
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
          ports: [{ containerPort: 443 }]
          volumeMounts:
            - { name: conf, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf }
            - { name: certs, mountPath: /certs }
      volumes:
        - { name: conf, configMap: { name: keyorix-tls-nginx-conf } }
        - { name: certs, secret: { secretName: keyorix-tls-cert } }
---
apiVersion: v1
kind: Service
metadata: { name: keyorix-tls, namespace: ${J1_NS} }
spec:
  selector: { app: keyorix-tls }
  ports: [{ port: 443, targetPort: 443 }]
EOF
kubectl apply -f "$WORK_DIR/tls-proxy.yaml" >/dev/null
kubectl -n "$J1_NS" rollout status deploy/keyorix-tls --timeout=60s >/dev/null

# patch_ca_trust <namespace> <deployment> <container>: mounts the test CA and
# sets SSL_CERT_FILE so a distroless Go binary (operator/agent) trusts the
# throwaway proxy above. Neither chart exposes a caBundle knob (a real
# production gap for anyone running Keyorix behind a private CA -- noted in
# Session J's report, not fixed here) so this patches the live Deployment
# directly; it is NOT part of either chart.
#
# Uses a STRATEGIC merge patch, not a JSON patch: the operator's Deployment
# has no pre-existing spec.template.spec.volumes/containers[].volumeMounts/
# containers[].env, but keyorix-sync's DOES (its own config-file mount) --
# `kubectl patch --type=json` with `"op":"add","path":".../volumes"` (no
# trailing `/-`) REPLACES the whole array wholesale, silently deleting the
# config volume that already lived there and crash-looping the agent
# (confirmed live: exactly this happened while writing this script -- the
# k8s-sync pod entered CrashLoopBackOff after this same patch that worked
# fine for the operator). A strategic merge patch merges these three fields
# by their `name` key (the Kubernetes API's own patchMergeKey for
# PodSpec.volumes, Container.volumeMounts, and Container.env) regardless of
# whether the target array is empty or already populated -- the one form
# that's correct for both charts without special-casing.
patch_ca_trust() {
    local ns="$1" deploy="$2" container="$3"
    kubectl -n "$ns" get configmap keyorix-test-ca >/dev/null 2>&1 \
        || kubectl -n "$ns" create configmap keyorix-test-ca --from-file=ca.crt="$WORK_DIR/tls.crt" >/dev/null
    kubectl -n "$ns" patch deployment "$deploy" --type=strategic -p "$(cat <<PATCHEOF
{"spec":{"template":{"spec":{
  "volumes":[{"name":"test-ca","configMap":{"name":"keyorix-test-ca"}}],
  "containers":[{"name":"${container}","volumeMounts":[{"name":"test-ca","mountPath":"/test-certs"}],"env":[{"name":"SSL_CERT_FILE","value":"/test-certs/ca.crt"}]}]
}}}}
PATCHEOF
)" >/dev/null
    kubectl -n "$ns" rollout status "deployment/${deploy}" --timeout=60s >/dev/null
}

# ============================================================================
# J3 -- operator e2e
# ============================================================================
J3_NS="${NS_PREFIX}-j3"
log "J3: installing the operator (namespace-scoped default) in $J3_NS"
kubectl delete namespace "$J3_NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
kx machine create --name k8s-e2e-operator --project default --type k8s --description "k8s-e2e run.sh" >/dev/null
kx machine grant-role k8s-e2e-operator --project default --role viewer >/dev/null
OPERATOR_TOKEN="$(kx machine token issue k8s-e2e-operator --name run-sh --project default | awk '/^Token:/{print $2}')"
[ -n "$OPERATOR_TOKEN" ] || fail "issuing the operator's machine token failed"

helm install keyorix-operator "$REPO_ROOT/deploy/helm/keyorix-operator" -n "$J3_NS" --create-namespace \
    --set image.repository=keyorix-operator --set image.tag="$IMAGE_TAG" \
    --set allowedServers[0]="https://${TLS_HOST}" \
    --wait --timeout 60s
patch_ca_trust "$J3_NS" "keyorix-operator-keyorix-operator" "manager"

kx secret create --name k8s-e2e-operator-secret --value 'k8s-e2e-operator-value' --project 1 --environment 1 >/dev/null
kubectl -n "$J3_NS" create secret generic keyorix-token --from-literal=token="$OPERATOR_TOKEN" >/dev/null
kubectl -n "$J3_NS" label secret keyorix-token secrets.keyorix.io/token-secret=true >/dev/null

cat >"$WORK_DIR/keyorixsecret.yaml" <<EOF
apiVersion: secrets.keyorix.io/v1alpha1
kind: KeyorixSecret
metadata: { name: k8s-e2e, namespace: ${J3_NS} }
spec:
  server: https://${TLS_HOST}
  tokenSecretRef: { name: keyorix-token, key: token }
  refreshInterval: 30s
  target: { name: k8s-e2e-operator-target, type: Opaque }
  data:
    - secretKey: VALUE
      ref: default/development/k8s-e2e-operator-secret
EOF
kubectl apply -f "$WORK_DIR/keyorixsecret.yaml" >/dev/null
for _ in $(seq 1 30); do
    [ "$(kubectl -n "$J3_NS" get keyorixsecret k8s-e2e -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)" = "True" ] && break
    sleep 2
done
[ "$(kubectl -n "$J3_NS" get keyorixsecret k8s-e2e -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)" = "True" ] \
    || fail "operator KeyorixSecret never reached Ready=True: $(kubectl -n "$J3_NS" get keyorixsecret k8s-e2e -o jsonpath='{.status.conditions[0].message}' 2>/dev/null)"
GOT="$(kubectl -n "$J3_NS" get secret k8s-e2e-operator-target -o jsonpath='{.data.VALUE}' | base64 -d)"
[ "$GOT" = "k8s-e2e-operator-value" ] || fail "operator-synced value mismatch: got '$GOT'"
log "J3: operator sync OK"

# ============================================================================
# J4 -- k8s-sync agent e2e (sync + prune-on-mapping-removal)
# ============================================================================
J4_NS="${NS_PREFIX}-j4"
log "J4: installing the k8s-sync agent in $J4_NS"
kubectl delete namespace "$J4_NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
kubectl create namespace "$J4_NS" >/dev/null
kx machine create --name k8s-e2e-sync --project default --type k8s --description "k8s-e2e run.sh" >/dev/null
kx machine grant-role k8s-e2e-sync --project default --role viewer >/dev/null
SYNC_TOKEN="$(kx machine token issue k8s-e2e-sync --name run-sh --project default | awk '/^Token:/{print $2}')"
[ -n "$SYNC_TOKEN" ] || fail "issuing the k8s-sync machine token failed"
kubectl -n "$J4_NS" create secret generic keyorix-sync-token --from-literal=token="$SYNC_TOKEN" >/dev/null

kx secret create --name k8s-e2e-sync-a --value 'k8s-e2e-sync-value-a' --project 1 --environment 3 >/dev/null
kx secret create --name k8s-e2e-sync-b --value 'k8s-e2e-sync-value-b' --project 1 --environment 3 >/dev/null

cat >"$WORK_DIR/k8ssync-values.yaml" <<EOF
image: { repository: keyorix-k8s-sync, tag: ${IMAGE_TAG} }
keyorix:
  url: https://${TLS_HOST}
  projectID: 1
  interval: 20s
  tokenSecret: { name: keyorix-sync-token, key: token }
mappings:
  - { ref: production/k8s-e2e-sync-a, namespace: ${J4_NS}, name: k8s-e2e-sync-target, key: VALUE_A }
  - { ref: production/k8s-e2e-sync-b, namespace: ${J4_NS}, name: k8s-e2e-sync-target, key: VALUE_B }
EOF
helm install keyorix-sync "$REPO_ROOT/deploy/helm/keyorix-k8s-sync" -n "$J4_NS" \
    -f "$WORK_DIR/k8ssync-values.yaml" --wait --timeout 60s
patch_ca_trust "$J4_NS" "keyorix-sync-keyorix-k8s-sync" "keyorix-k8s-sync"

for _ in $(seq 1 30); do
    kubectl -n "$J4_NS" get secret k8s-e2e-sync-target >/dev/null 2>&1 && break
    sleep 2
done
kubectl -n "$J4_NS" get secret k8s-e2e-sync-target >/dev/null 2>&1 || fail "k8s-sync target Secret was never created"
GOT_A="$(kubectl -n "$J4_NS" get secret k8s-e2e-sync-target -o jsonpath='{.data.VALUE_A}' | base64 -d)"
GOT_B="$(kubectl -n "$J4_NS" get secret k8s-e2e-sync-target -o jsonpath='{.data.VALUE_B}' | base64 -d)"
[ "$GOT_A" = "k8s-e2e-sync-value-a" ] || fail "k8s-sync VALUE_A mismatch: got '$GOT_A'"
[ "$GOT_B" = "k8s-e2e-sync-value-b" ] || fail "k8s-sync VALUE_B mismatch: got '$GOT_B'"
log "J4: sync OK (both keys)"

log "J4: removing the VALUE_A mapping -- regression check for PR #2286's pruning fix"
cat >"$WORK_DIR/k8ssync-values-pruned.yaml" <<EOF
image: { repository: keyorix-k8s-sync, tag: ${IMAGE_TAG} }
keyorix:
  url: https://${TLS_HOST}
  projectID: 1
  interval: 20s
  tokenSecret: { name: keyorix-sync-token, key: token }
mappings:
  - { ref: production/k8s-e2e-sync-b, namespace: ${J4_NS}, name: k8s-e2e-sync-target, key: VALUE_B }
EOF
helm upgrade keyorix-sync "$REPO_ROOT/deploy/helm/keyorix-k8s-sync" -n "$J4_NS" \
    -f "$WORK_DIR/k8ssync-values-pruned.yaml" --wait --timeout 60s
patch_ca_trust "$J4_NS" "keyorix-sync-keyorix-k8s-sync" "keyorix-k8s-sync"
for _ in $(seq 1 30); do
    [ "$(kubectl -n "$J4_NS" get secret k8s-e2e-sync-target -o jsonpath='{.data.VALUE_A}' 2>/dev/null)" = "" ] && break
    sleep 2
done
[ "$(kubectl -n "$J4_NS" get secret k8s-e2e-sync-target -o jsonpath='{.data.VALUE_A}' 2>/dev/null)" = "" ] \
    || fail "VALUE_A was never pruned after its mapping was removed -- PR #2286's fix regressed"
log "J4: prune-only-own-keys OK"

# ============================================================================
# J5 -- ESO webhook provider e2e
# ============================================================================
J5_NS="${NS_PREFIX}-eso"
log "J5: installing the External Secrets Operator (real ESO, not a stub) in $J5_NS"
kubectl delete namespace "$J5_NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo update external-secrets >/dev/null
helm install external-secrets external-secrets/external-secrets -n "$J5_NS" --create-namespace \
    --wait --timeout 120s >/dev/null

kx machine create --name k8s-e2e-eso --project default --type other --description "k8s-e2e run.sh" >/dev/null
kx machine grant-role k8s-e2e-eso --project default --role viewer >/dev/null
ESO_TOKEN="$(kx machine token issue k8s-e2e-eso --name run-sh --project default | awk '/^Token:/{print $2}')"
[ -n "$ESO_TOKEN" ] || fail "issuing the ESO machine token failed"
kubectl -n "$J5_NS" create secret generic keyorix-machine-token --from-literal=token="$ESO_TOKEN" >/dev/null
kubectl -n "$J5_NS" label secret keyorix-machine-token external-secrets.io/type=webhook >/dev/null
kubectl -n "$J5_NS" create secret generic keyorix-ca --from-file=ca.crt="$WORK_DIR/tls.crt" >/dev/null

kx secret create --name k8s-e2e-eso-secret --value 'k8s-e2e-eso-value' --project 1 --environment 3 >/dev/null

sed -e "s|https://keyorix.internal|https://${TLS_HOST}|" \
    -e "s|namespace: external-secrets|namespace: ${J5_NS}|g" \
    "$REPO_ROOT/deploy/eso/cluster-secret-store.yaml" >"$WORK_DIR/cluster-secret-store.yaml"
kubectl apply -f "$WORK_DIR/cluster-secret-store.yaml" >/dev/null

J5_TARGET_NS="${NS_PREFIX}-j5-target"
kubectl create namespace "$J5_TARGET_NS" >/dev/null
sed -e "s|namespace: app|namespace: ${J5_TARGET_NS}|" \
    -e "s|app/production/db-password|default/production/k8s-e2e-eso-secret|" \
    -e "s|app/production/api-key|default/production/k8s-e2e-eso-secret|" \
    "$REPO_ROOT/deploy/eso/external-secret.yaml" >"$WORK_DIR/external-secret.yaml"
kubectl apply -f "$WORK_DIR/external-secret.yaml" >/dev/null

for _ in $(seq 1 30); do
    [ "$(kubectl -n "$J5_TARGET_NS" get externalsecret db-creds -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)" = "True" ] && break
    sleep 3
done
[ "$(kubectl -n "$J5_TARGET_NS" get externalsecret db-creds -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)" = "True" ] \
    || fail "ExternalSecret never reached Ready=True: $(kubectl -n "$J5_TARGET_NS" get externalsecret db-creds -o jsonpath='{.status.conditions[0].message}' 2>/dev/null)"
GOT="$(kubectl -n "$J5_TARGET_NS" get secret db-creds -o jsonpath='{.data.DB_PASSWORD}' | base64 -d)"
[ "$GOT" = "k8s-e2e-eso-value" ] || fail "ESO-synced value mismatch: got '$GOT'"
log "J5: ESO webhook sync OK"

echo ""
echo "K8S E2E PASSED (J1-J5)"
