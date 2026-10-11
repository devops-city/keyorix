#!/usr/bin/env bash
# scripts/docker-webui-embedded-check.sh -- #2752: assert that an image built from
# server/Dockerfile actually SERVES the web dashboard at /, rather than the committed
# "Web UI not bundled in this build" placeholder.
#
# Why a boot-and-GET check and not a file check: `server/webui/embed.go`'s
# `//go:embed all:dist` bakes whatever was on disk at compile time into the binary, so
# nothing on the image's filesystem distinguishes the two cases -- the only place the
# difference is observable is the HTTP response the running server gives for /. That is
# also the thing a customer experiences, which is what #2752 was reported as.
#
# The check is deliberately BOTH directions, so it cannot pass vacuously:
#   1. the response must NOT be the placeholder (a negative, the reported symptom), and
#   2. it MUST be a real Vite build -- a <script> referencing /assets/ and the SPA's own
#      root div (a positive; an empty 200, an error page, or a stray index.html with no
#      bundle would fail this even though it is "not the placeholder").
# `HasRealBuild()` in embed.go uses the same assets/ signal for its startup log.
#
# Usage:
#   scripts/docker-webui-embedded-check.sh <image-tag>
#
# Build an image to point it at first, e.g.:
#   docker build -f server/Dockerfile -t keyorix-server:webui-check .
#   docker build -f server/Dockerfile --build-arg BUILD_TAGS=noaws,noazure,nogcp \
#       -t keyorix-server-airgap:webui-check .
#
# Runs the container with --network none (loopback only, like scripts/airgap-e2e.sh):
# this never needs outbound network, and running it that way means the check is equally
# valid for the air-gapped variant.
set -euo pipefail

IMAGE="${1:-}"
if [ -z "$IMAGE" ]; then
    echo "usage: $0 <image-tag>" >&2
    exit 2
fi

ENGINE="${CONTAINER_ENGINE:-docker}"
CONTAINER="keyorix-webui-check-$$"
WORK_DIR="$(mktemp -d)"

cleanup() {
    $ENGINE rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
    echo "" >&2
    echo "WEB UI EMBED CHECK FAILED: $1" >&2
    echo "" >&2
    echo "--- container logs ---" >&2
    $ENGINE logs "$CONTAINER" 2>&1 | tail -40 >&2 || true
    exit 1
}

# The container runs as uid 1001 (see server/Dockerfile), so the bind-mounted data dir
# must be writable by it.
chmod 777 "$WORK_DIR"

MASTER_PW="webui-check-master-password-$$"

# Same bootstrap sequence scripts/airgap-e2e.sh uses, and the same one QUICK_START.md
# documents: the server refuses to start without a config, and admin init only creates
# one relative to the working directory (an absolute --config path is rejected outright).
run_admin() {
    $ENGINE run --rm --network none --workdir /app/data \
        -v "$WORK_DIR:/app/data" \
        -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
        --entrypoint /app/keyorix-server \
        "$IMAGE" "$@"
}

echo "==> admin init / encryption init / migrate"
# --dev: this check GETs / over plain HTTP on the container loopback.
run_admin admin init --dev --config ./keyorix.yaml >/dev/null 2>&1 || fail "admin init failed"
run_admin admin encryption init --config ./keyorix.yaml >/dev/null 2>&1 || fail "admin encryption init failed"
run_admin admin migrate --config ./keyorix.yaml >/dev/null 2>&1 || fail "admin migrate failed"

echo "==> starting $IMAGE (--network none)"
$ENGINE run -d --name "$CONTAINER" --network none --workdir /app/data \
    -v "$WORK_DIR:/app/data" \
    -e KEYORIX_CONFIG_PATH=/app/data/keyorix.yaml \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PW" \
    --entrypoint /app/keyorix-server \
    "$IMAGE" >/dev/null

echo "==> waiting for /health"
healthy=0
for _ in $(seq 1 60); do
    if $ENGINE exec "$CONTAINER" wget -q --spider "http://127.0.0.1:8080/health" 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done
[ "$healthy" = "1" ] || fail "the server never answered /health within 60s"

echo "==> GET /"
# -O- to stdout; the response is a small HTML document either way.
BODY="$($ENGINE exec "$CONTAINER" wget -q -O- "http://127.0.0.1:8080/" 2>/dev/null)" ||
    fail "GET / did not return successfully"

# (1) Negative: not the placeholder. Matches the placeholder's own wording in
# server/webui/dist/index.html, and the server's startup log line for the same state.
if printf '%s' "$BODY" | grep -qiE 'does not bundle the web dashboard|Web UI not bundled|Keyorix API server'; then
    fail "/ served the placeholder page -- the image does not embed the web dashboard (#2752)"
fi

# (2) Positive: a real Vite build. Both signals, so a non-placeholder page that is still
# not the dashboard cannot pass.
printf '%s' "$BODY" | grep -q '/assets/' ||
    fail "/ returned something that is not the placeholder but references no /assets/ bundle"
printf '%s' "$BODY" | grep -qE '<script[^>]+src="/assets/' ||
    fail "/ returned no <script src=\"/assets/...\"> -- not a Vite build output"
printf '%s' "$BODY" | grep -q 'id="root"' ||
    fail "/ returned no SPA root element (id=\"root\")"

# The server's own startup log is independent corroboration: embed.go logs the
# not-bundled line only when assets/ is absent.
if $ENGINE logs "$CONTAINER" 2>&1 | grep -q 'Web UI not bundled in this build'; then
    fail "the server logged 'Web UI not bundled in this build' even though / looked like a real build"
fi

# And the asset the page references must actually be servable, not just named.
ASSET_PATH="$(printf '%s' "$BODY" | grep -oE '/assets/[A-Za-z0-9._-]+\.js' | head -1)"
[ -n "$ASSET_PATH" ] || fail "could not extract an /assets/*.js path from /"
$ENGINE exec "$CONTAINER" wget -q --spider "http://127.0.0.1:8080$ASSET_PATH" 2>/dev/null ||
    fail "the referenced bundle $ASSET_PATH is not served (index.html embedded without its assets)"

echo ""
echo "WEB UI EMBED CHECK PASSED for $IMAGE (serves a real dashboard at /, bundle $ASSET_PATH reachable)"
