# Web UI stage (#2752). Builds the dashboard so the Go stage below can embed it into
# the server binary -- `docker build -f server/Dockerfile .` alone now produces an image
# that serves the real dashboard at /, for BOTH build-tag variants.
#
# Before this stage existed, every image this Dockerfile produced -- including the
# published ghcr.io/keyorixhq/keyorix-server and its -airgap variant -- served the
# committed placeholder page ("Web UI not bundled in this build"), because the only
# thing git tracks under server/webui/dist/ is that placeholder and nothing in the
# build ran `pnpm build` first. The release TARBALLS never had this gap: `make release`
# depends on populate-webui-dist. This stage is the Docker equivalent of that
# dependency, and deliberately reproduces `make build-ui`/populate-webui-dist's own
# steps (pnpm install --frozen-lockfile, pnpm build, replace server/webui/dist with
# web/dist) rather than inventing a second way to do it.
#
# --platform=$BUILDPLATFORM: the output is static JS/CSS, identical for every target
# arch, so this never needs to run under QEMU emulation -- same reasoning as the Go
# stage below.
#
# Pinned by digest (a multi-arch manifest-list digest, so it resolves on any builder
# arch), matching every other base image in this file. pnpm comes from corepack, which
# honours web/package.json's own `packageManager` field including its integrity hash --
# so the pnpm version and its checksum are pinned by the repo, not by this file.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS webui
WORKDIR /web
# Manifests first, so a source-only change does not re-resolve dependencies.
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# --frozen-lockfile: fail rather than silently resolve something the lockfile doesn't
# pin. --ignore-scripts: same supply-chain rationale as .github/workflows/web-ci.yml's
# own install step -- a transitive package's postinstall must not run arbitrary code in
# the image build.
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts
COPY web/ ./
RUN pnpm build && test -d dist/assets

# Build stage. Pinned to $BUILDPLATFORM (the runner's own arch, never emulated)
# even when cross-building for a different $TARGETPLATFORM: the Go toolchain
# cross-compiles natively via GOOS/GOARCH below, which is far faster than
# running the whole build stage under QEMU emulation for the target arch.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS builder
RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Injected at build time so the image reports its real release version at runtime
# (e.g. /health, /system/info). Defaults keep ad-hoc `docker build` working; the
# docker-publish workflow passes the git tag + sha. Mirrors the Makefile LDFLAGS.
ARG VERSION=dev
ARG GIT_COMMIT=none
# Set by buildx to the requested target platform, independent of the builder's
# own (BUILDPLATFORM) arch above -- same CGO_ENABLED=0 cross-compile shape the
# release Makefile already uses (modernc.org/sqlite is pure Go, no cgo needed).
ARG TARGETOS
ARG TARGETARCH
# BUILD_TAGS (ADR-109 step 6, B3/S4): empty builds the FULL server (default,
# every existing caller of this Dockerfile is unaffected); the docker-publish
# workflow's air-gapped job passes "noaws,noazure,nogcp" for the AIR-GAPPED
# image variant (<ver>-airgap) -- Vault and Kubernetes stay in that profile
# per ADR-109's open-questions decision. Never "lean" -- that older, narrower
# tag is a separate, smaller exclusion (rotation/awsiam + evidencesink/
# objectstore only) this image has never built with.
ARG BUILD_TAGS=
# Replace the committed placeholder dist/ with the real build before compiling, exactly
# as populate-webui-dist does (rm -rf, then copy web/dist over it) -- server/webui/
# embed.go's `//go:embed all:dist` picks up whatever is there at compile time, so this
# must happen before `go build` and after `COPY . .` (which brings the placeholder in).
# Both BUILD_TAGS variants go through this line: the air-gapped image gets the same real
# dashboard, which is what ADR-109's "one file" air-gap profile claims and what the
# published -airgap image did not deliver.
RUN rm -rf server/webui/dist
COPY --from=webui /web/dist/ ./server/webui/dist/
RUN set -- \
    "-s -w" \
    "-X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Version=${VERSION}" \
    "-X github.com/keyorixhq/keyorix/internal/version.Commit=${GIT_COMMIT}" && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -tags "${BUILD_TAGS}" -ldflags "$*" \
    -o bin/keyorix-server ./server

# Runtime stage
#
# NOTE on distroless (backlog #242): entrypoint.sh needs a real shell plus `wget`,
# `mktemp`, `trap`, and `seq` for its first-boot admin-bootstrap logic (waiting for
# /health, then POSTing the initial admin via wget --post-file). distroless/static
# and distroless/base have no shell or busybox utilities at all, so a direct swap
# would break that bootstrap flow. Moving the bootstrap into the Go binary itself
# (invoked via a flag) would remove the need for the shell script entirely and let
# this image go fully distroless, but that's a larger refactor than this hardening
# round should attempt — tracked as a follow-up. In the meantime we keep Alpine but
# strip the `apk` package manager (binary + package db) once the packages we need
# are installed, so RCE inside this container can no longer `apk add` extra tooling.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates tzdata && \
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk && \
    addgroup -g 1001 keyorix && \
    adduser -D -s /bin/sh -u 1001 -G keyorix keyorix
WORKDIR /app
COPY --from=builder /app/bin/keyorix-server .
COPY --from=builder /app/server/entrypoint.sh .
RUN chmod +x entrypoint.sh && \
    mkdir -p data keys && chown -R keyorix:keyorix /app && \
    chmod 0700 data keys
USER 1001:1001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1"]
CMD ["./entrypoint.sh"]
