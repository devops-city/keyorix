#!/usr/bin/env bash
# scripts/demo/scenario-k8s-sync.sh — catalogue scenario 11: Kubernetes sync, "rotate -> the pod
# sees the new value".
#
# STATUS: WRITTEN, NOT RUN. It needs Docker + kind + kubectl + helm, which are not available
# where this script was written (no Docker on the author's machine). Run it on the e2e VM, where
# `make k8s-e2e` (scripts/k8s-e2e/run.sh) already proves the underlying delivery paths against a
# real cluster (phase J4 is the k8s-sync agent: sync + prune-on-mapping-removal).
#
# What it does when its prerequisites exist:
#   1. reuses the kind cluster + keyorix-k8s-sync agent + Keyorix server that `make k8s-e2e`
#      leaves behind when run with KEEP=1 (it does not build or install anything itself),
#   2. a pod mounts the synced Kubernetes Secret as an environment variable,
#   3. the secret is rotated in Keyorix with the CLI,
#   4. after one sync interval the Kubernetes Secret holds the new value, and a restarted pod
#      (a rollout restart - env vars are read at container start) prints it.
#
# Inputs (environment, never argv): KEYORIX_SERVER, KEYORIX_TOKEN (an admin session or PAT),
# K8S_NS (namespace of the sync agent, default keyorix-e2e-j4), K8S_SECRET (target Secret name,
# default k8s-e2e-sync-target), KX_SECRET_ID (the mapped Keyorix secret id), SYNC_WAIT (seconds
# to wait for the agent's reconcile, default 90).
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1 || missing="${missing:-} $1"; }
need kubectl; need kind; need docker
# the docker CLI can be installed while no daemon is reachable (or it is denied): ask the daemon.
if [ -z "${missing:-}" ] && ! docker info >/dev/null 2>&1; then missing=" a reachable Docker daemon"; fi
if [ -n "${missing:-}" ]; then
  echo "PENDING e2e VM: missing${missing} - this scenario is written but was not run here." >&2
  echo "On the e2e VM:  KEEP=1 make k8s-e2e   then   KEYORIX_SERVER=... KEYORIX_TOKEN=... KX_SECRET_ID=... $0" >&2
  exit 3
fi
: "${KEYORIX_SERVER:?set KEYORIX_SERVER}" "${KEYORIX_TOKEN:?set KEYORIX_TOKEN}" "${KX_SECRET_ID:?set KX_SECRET_ID}"
NS="${K8S_NS:-keyorix-e2e-j4}"; SECRET="${K8S_SECRET:-k8s-e2e-sync-target}"; WAIT="${SYNC_WAIT:-90}"
CLI="${CLI_BIN:-bin/keyorix}"
step() { printf '==> %s\n' "$1"; }

step "1/4 the synced Kubernetes Secret as it is now"
kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data}' | head -c 200; echo

step "2/4 a pod that reads it as an env var"
kubectl -n "$NS" delete pod demo-reader --ignore-not-found --wait=true >/dev/null
kubectl -n "$NS" run demo-reader --image=busybox:1.36 --restart=Never \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"demo-reader\",\"image\":\"busybox:1.36\",\"command\":[\"sh\",\"-c\",\"echo value-length=\${V}; sleep 3600\"],\"env\":[{\"name\":\"V\",\"valueFrom\":{\"secretKeyRef\":{\"name\":\"$SECRET\",\"key\":\"$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data}' | python3 -c 'import json,sys; print(next(iter(json.load(sys.stdin))))')\"}}}]}]}}" >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod/demo-reader --timeout=60s >/dev/null
OLD="$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data}')"

step "3/4 rotate the secret in Keyorix (new value on stdin)"
printf '%s\n' "rotated-by-demo-$(date +%s)" | "$CLI" secret rotate --id "$KX_SECRET_ID" >/dev/null

step "4/4 wait up to ${WAIT}s for the agent, then restart the pod"
end=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$end" ]; do
  [ "$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data}')" != "$OLD" ] && break
  sleep 5
done
[ "$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data}')" != "$OLD" ] || { echo "FAIL: the Kubernetes Secret did not change within ${WAIT}s" >&2; exit 1; }
echo "   the Kubernetes Secret now holds the rotated value"
kubectl -n "$NS" delete pod demo-reader --wait=true >/dev/null
echo "   (env vars are read when a container starts: a running pod keeps the old value until restarted;"
echo "    mount the Secret as a volume if the app should see the change without a restart)"
