#!/usr/bin/env bash
# scripts/k8s-e2e/multi-replica.sh -- two server replicas on one shared keys
# volume in a real kind cluster (HA-READY-1, docs/multi-replica-keys.md).
#
# MANUAL target (needs Docker + kind; run it on the e2e VM). It needs the Helm
# chart to honour server.replicas (#3305). Until the chart renders
# storage.encryption.key_dir_lock itself, a helm post-renderer adds it.
#
# Flow:
#   0. Preflight; the chart renders server.replicas=2, else stop (#3305 not merged).
#   1. kind cluster (one node), server + web images built from this checkout and
#      loaded; a hostPath PersistentVolume offered as ReadWriteMany for the keys
#      (one node, so both pods share one directory and one kernel's flock: the
#      shape of an RWX volume whose flock is enforced across clients).
#   2. Phase A, default flock: install with server.replicas=2. Expected: one pod
#      Ready, the other refusing with "encryption key lock". This is the red
#      premise; the phase fails if both become Ready.
#   3. Phase B, key_dir_lock: database: reinstall on a fresh volume. Both pods Ready
#      on one key set; bootstrap admin + MFA; a secret written through pod 1 reads
#      back through pod 2; deleting pod 1 brings a replacement that reads it too;
#      a rolling restart completes with both Ready.
#   4. Cleanup: the namespace, the PV, and the cluster unless
#      KEYORIX_KMR_KEEP_CLUSTER=1.
#
# Names carry the session tag (cluster ha-ready-1-kmr, namespace kmr) so the
# script never touches another session's resources on a shared VM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KEYORIX_KMR_CLUSTER:-ha-ready-1-kmr}"
KEEP_CLUSTER="${KEYORIX_KMR_KEEP_CLUSTER:-0}"
IMAGE_TAG="${KEYORIX_KMR_IMAGE_TAG:-kmr}"
NS="kmr"
REL="kmr"
PV_NAME="kmr-keys-rwx"
SC_NAME="kmr-rwx"
NODE_DIR="/var/local/kmr-keys"
WORK_DIR="$(mktemp -d)"
PORT_FORWARD_PIDS=()

fail() { echo "" >&2; echo "MULTI-REPLICA E2E FAILED: $1" >&2; exit 1; }
log() { echo "==> $1"; }

cleanup() {
    log "Cleaning up"
    for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
    kubectl delete namespace "$NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
    kubectl delete pv "$PV_NAME" --ignore-not-found >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
    if [ "$KEEP_CLUSTER" != "1" ]; then
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- 0. preflight ---
for bin in docker kind helm kubectl go; do
    command -v "$bin" >/dev/null 2>&1 || fail "$bin is required and not on PATH"
done
docker info >/dev/null 2>&1 || fail "Docker daemon not reachable"

ADMIN_PASSWORD='Kmr-Replicas-Passw0rd!'
HELM_SECRET_VALUES="$WORK_DIR/secret-values.yaml"
(umask 077 && printf 'auth:\n  masterPassword: "kmr-master-password"\n  adminPassword: "%s"\npostgresql:\n  auth:\n    password: "kmr-db-password"\n' \
    "$ADMIN_PASSWORD" >"$HELM_SECRET_VALUES")
HA_SETS=(
    --set server.replicas=2
    --set server.keysPersistence.enabled=true
    --set server.keysPersistence.accessMode=ReadWriteMany
    --set server.keysPersistence.storageClass="$SC_NAME"
    --set server.image.repository=keyorix-server --set server.image.tag="$IMAGE_TAG"
    --set web.image.repository=keyorix-web --set web.image.tag="$IMAGE_TAG"
)
helm template "$REL" "$REPO_ROOT/deploy/helm/keyorix" -f "$HELM_SECRET_VALUES" "${HA_SETS[@]}" >"$WORK_DIR/render.yaml" \
    || fail "helm template with server.replicas=2 failed"
grep -q '^  replicas: 2$' "$WORK_DIR/render.yaml" \
    || fail "the chart does not honour server.replicas (needs #3305 merged)"

# Adds key_dir_lock: database beside dek_path in the rendered server config.
POST_RENDERER="$WORK_DIR/key-dir-lock-database.sh"
cat >"$POST_RENDERER" <<'EOF'
#!/bin/sh
exec sed -E 's#^( *)dek_path: "/app/keys/data.key"$#&\n\1key_dir_lock: database#'
EOF
chmod +x "$POST_RENDERER"

# --- 1. cluster, images, RWX volume ---
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "Creating kind cluster $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 120s
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
log "Building images (:$IMAGE_TAG)"
docker build -q -t "keyorix-server:${IMAGE_TAG}" -f "$REPO_ROOT/server/Dockerfile" "$REPO_ROOT" >/dev/null
docker build -q -t "keyorix-web:${IMAGE_TAG}" -f "$REPO_ROOT/web/Dockerfile" "$REPO_ROOT/web" >/dev/null
kind load docker-image "keyorix-server:${IMAGE_TAG}" "keyorix-web:${IMAGE_TAG}" --name "$CLUSTER_NAME" >/dev/null

log "Building the CLI"
CLI_BIN="$WORK_DIR/keyorix"
(cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$CLI_BIN" .)
CLI_HOME="$WORK_DIR/cli-home"
mkdir -p "$CLI_HOME"
kx() { HOME="$CLI_HOME" "$CLI_BIN" "$@"; }
totp() { (cd "$REPO_ROOT" && GOWORK=off go run scripts/totpgen/main.go "$@"); }

fresh_volume() {
    kubectl delete namespace "$NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
    kubectl delete pv "$PV_NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true
    docker exec "${CLUSTER_NAME}-control-plane" sh -c "rm -rf '$NODE_DIR' && mkdir -p '$NODE_DIR' && chown 1001:1001 '$NODE_DIR' && chmod 0700 '$NODE_DIR'"
    kubectl apply -f - >/dev/null <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${SC_NAME}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${PV_NAME}
spec:
  capacity:
    storage: 1Gi
  accessModes: [ReadWriteMany]
  persistentVolumeReclaimPolicy: Delete
  storageClassName: ${SC_NAME}
  hostPath:
    path: ${NODE_DIR}
    type: Directory
EOF
}

server_pods() {
    kubectl -n "$NS" get pods -l app.kubernetes.io/component=server -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
}
ready_count() {
    kubectl -n "$NS" get pods -l app.kubernetes.io/component=server \
        -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' | grep -c '^true$' || true
}

port_forward() {
    # port_forward <target> <local>:<remote>; registers the PID for cleanup.
    kubectl -n "$NS" port-forward "$1" "$2" >/dev/null 2>&1 &
    PORT_FORWARD_PIDS+=("$!")
    for _ in $(seq 1 30); do
        (exec 3<>"/dev/tcp/127.0.0.1/${2%%:*}") 2>/dev/null && exec 3>&- && return 0
        sleep 1
    done
    fail "port-forward $1 never became reachable"
}

# --- 2. Phase A: default flock ---
log "Phase A: server.replicas=2 with the default key_dir_lock (flock)"
fresh_volume
helm install "$REL" "$REPO_ROOT/deploy/helm/keyorix" -n "$NS" --create-namespace \
    -f "$HELM_SECRET_VALUES" "${HA_SETS[@]}" >/dev/null
for _ in $(seq 1 36); do
    [ "$(ready_count)" -ge 1 ] && break
    sleep 5
done
sleep 30
READY="$(ready_count)"
[ "$READY" = "2" ] && fail "Phase A: both replicas became Ready on one key directory with flock -- the red premise did not reproduce (is flock not enforced here?)"
[ "$READY" = "1" ] || fail "Phase A: expected exactly one Ready replica, got $READY"
REFUSED=""
for p in $(server_pods); do
    if kubectl -n "$NS" logs "$p" --all-containers --previous 2>/dev/null | grep -q "encryption key lock" \
        || kubectl -n "$NS" logs "$p" --all-containers 2>/dev/null | grep -q "encryption key lock"; then
        REFUSED="$p"
    fi
done
[ -n "$REFUSED" ] || fail "Phase A: no replica logged the key-lock refusal"
log "Phase A: as expected, $REFUSED refuses to start (encryption key lock)"
helm uninstall "$REL" -n "$NS" --wait >/dev/null

# --- 3. Phase B: key_dir_lock: database ---
log "Phase B: server.replicas=2 with key_dir_lock: database"
fresh_volume
helm install "$REL" "$REPO_ROOT/deploy/helm/keyorix" -n "$NS" --create-namespace \
    -f "$HELM_SECRET_VALUES" "${HA_SETS[@]}" --post-renderer "$POST_RENDERER" --wait --timeout 300s >/dev/null \
    || fail "Phase B: helm install --wait failed"
kubectl -n "$NS" get configmap -o yaml | grep -q 'key_dir_lock: database' || fail "Phase B: post-renderer did not set key_dir_lock"
[ "$(ready_count)" = "2" ] || fail "Phase B: expected 2 Ready replicas, got $(ready_count)"
read -r POD1 POD2 <<<"$(server_pods | tr '\n' ' ')"
docker exec "${CLUSTER_NAME}-control-plane" sh -c "ls '$NODE_DIR'" | grep -q '^dek.lock$' \
    && fail "Phase B: dek.lock exists on the shared volume (the server must take no key-directory flock)"
log "Phase B: both replicas Ready ($POD1, $POD2) on one key set"

port_forward "pod/$POD1" 18181:8080
port_forward "pod/$POD2" 18182:8080
KEYORIX_PASSWORD="$ADMIN_PASSWORD" kx login --server http://localhost:18181 --username admin >/dev/null || fail "login (pod 1) failed"
ENROLL_OUT="$(kx mfa enroll)" || fail "mfa enroll failed"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse the MFA secret"
KEYORIX_MFA_CODE="$(totp "$MFA_SECRET")" KEYORIX_PASSWORD="$ADMIN_PASSWORD" kx mfa activate >/dev/null || fail "mfa activate failed"
login() {
    KEYORIX_PASSWORD="$ADMIN_PASSWORD" KEYORIX_MFA_CODE="$(totp "$MFA_SECRET" 30)" \
        kx login --server "http://localhost:$1" --username admin >/dev/null || fail "login on :$1 failed"
}
login 18181
(cd "$CLI_HOME" && umask 077 && printf '%s' 'kmr-cross-replica-value' >./v.txt \
    && kx secret create --name kmr-cross-replica --from-file ./v.txt --project 1 --environment 1 >/dev/null) \
    || fail "secret create through pod 1 failed"
read_value() { kx secret get --id 1 --show-value | awk '/^Decrypted Value/{getline; getline; print}'; }
login 18182
[ "$(read_value)" = "kmr-cross-replica-value" ] || fail "pod 2 cannot read what pod 1 wrote"
log "Phase B: written through $POD1, read back through $POD2"

log "Phase B: delete $POD1; its replacement must start on the shared keys"
kubectl -n "$NS" delete pod "$POD1" --wait=true >/dev/null
kubectl -n "$NS" rollout status deploy -l app.kubernetes.io/component=server --timeout 180s >/dev/null 2>&1 \
    || kubectl -n "$NS" wait --for=condition=Ready pod -l app.kubernetes.io/component=server --timeout 180s >/dev/null
[ "$(ready_count)" = "2" ] || fail "after deleting a pod: expected 2 Ready replicas, got $(ready_count)"
NEW_POD="$(server_pods | grep -vx "$POD2" | head -1)"
port_forward "pod/$NEW_POD" 18183:8080
login 18183
[ "$(read_value)" = "kmr-cross-replica-value" ] || fail "the replacement pod cannot read the secret"

log "Phase B: rolling restart"
DEPLOY="$(kubectl -n "$NS" get deploy -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" rollout restart "deploy/$DEPLOY" >/dev/null
kubectl -n "$NS" rollout status "deploy/$DEPLOY" --timeout 300s >/dev/null || fail "rolling restart did not complete"
[ "$(ready_count)" = "2" ] || fail "after the rolling restart: expected 2 Ready replicas, got $(ready_count)"

log "MULTI-REPLICA E2E PASSED"
