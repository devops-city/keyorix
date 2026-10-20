# Build stage — the SPA is built with pnpm (the repo's package manager) on Node 22.
# All dependencies are needed (Vite et al. are devDependencies), so this is a
# full install, not --prod. Pinned to $BUILDPLATFORM: the compiled output is a
# static JS/CSS/HTML bundle with no architecture dependence, so this stage gets
# no benefit from running under the target arch, only the cost of QEMU
# emulation when TARGETPLATFORM differs from the runner's own arch.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder
# Exact version, not just the major (docker:S8543) — reproducible builds need
# a resolved pin, not a moving target. Corepack (bundled with node:22-alpine)
# fetches the pnpm tarball from the npm registry and verifies it against the
# registry-published integrity hash before activating it, same trust model as
# `npm install -g pnpm@<version>` used previously — but Scorecard's
# Pinned-Dependencies probe only ever recognizes an `npm install` as pinned
# when it's `npm ci` or a git+commit-hash spec (see isNpmUnpinnedDownload in
# ossf/scorecard), so a registry-version `npm install -g` is always flagged
# regardless of how exact the pin is (alert #635). Corepack isn't scanned by
# that npm-specific probe at all. --ignore-scripts (docker:S6505) on the pnpm
# workspace install below: pnpm's own default-deny (pnpm 10+) already blocks
# unlisted lifecycle scripts; web/pnpm-workspace.yaml's allowBuilds:
# esbuild: true still lets the actual build work.
RUN corepack enable && corepack prepare pnpm@11.19.0 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY . .
RUN pnpm build

# Production stage — nginx serves the static bundle and reverse-proxies the API
# (/api/ and /auth/) to the backend service. See nginx.conf.
#
# 2026-09-08: bumped from sha256:4a73073b... (nginx 1.31.5-alpine, built
# 2026-08-2x) to the current nginx:alpine digest below (same 1.31.5-alpine,
# rebuilt 2026-09-02) to pick up the Alpine 3.24 openssl security update
# (libcrypto3/libssl3 3.5.7-r0 -> 3.5.8-r0, CVE-2026-14456) baked into the
# upstream image. That rebuild did NOT also pick up util-linux's fix
# (libuuid stays 2.42.1-r0 in both digests) -- nginx's official image is a
# point-in-time snapshot of whatever Alpine 3.24's main repo had at BUILD
# time, and Alpine's own 3.24 branch had already shipped libuuid 2.42.3-r1
# (verified directly against https://dl-cdn.alpinelinux.org/alpine/v3.24/
# main/aarch64/APKINDEX.tar.gz) before upstream nginx's last rebuild picked
# it up. Waiting on nginx's next rebuild has no defined timeline, so the
# line below pulls the already-published fix from the SAME Alpine 3.24 repo
# this base image already trusts, pinned to an exact version for the same
# reproducibility reason the pnpm version above is pinned exactly rather
# than left to float. Closes CVE-2026-53612/53613/53614/76642/78408/78409/
# 78410 (util-linux, all in the libuuid sub-package this minimal image
# actually installs -- nothing else from util-linux is present here).
FROM nginx:alpine@sha256:72ba65eb42c10344912a84ff42408db7d34f2feb642204570ab8fc5ffd29f1d3 AS production
# v0.96.1: same pattern for pcre2 (CVE-2026-103111) and tiff (CVE-2026-4775),
# both HIGH. Checked 2026-10-13: the newest nginx:alpine digest still ships
# pcre2 10.48-r0 / tiff 4.7.1-r0, so no base-image bump carries the fix yet.
# Remove these two pins once the pinned base digest above includes
# pcre2>=10.49-r0 and tiff>=4.7.2-r0.
#
# The pins are MINIMUM versions (pkg>=ver), not exact revisions. Exact pins
# (libexpat=2.8.5-r0) broke the build on 2026-10-19 when Alpine 3.24 moved on to
# libexpat 2.9.0-r0 and dropped the old revision from the index ("unable to select
# packages ... breaks: world[libexpat=2.8.5-r0]"): release-dry-run, docker-publish
# and release would all fail at tag time. A floor keeps the security intent (never
# older than the fixed version) without breaking on the next revision bump.
# Floors and the CVE each one closes:
#   libuuid >= 2.42.3-r1   CVE-2026-53612/53613/53614/76642/78408/78409/78410
#   libexpat >= 2.8.5-r0   CVE-2026-93990 (HIGH)
#   pcre2   >= 10.49-r0    CVE-2026-103111 (HIGH)
#   tiff    >= 4.7.2-r0    CVE-2026-4775 (HIGH)
RUN apk update && apk add --no-cache --upgrade 'libuuid>=2.42.3-r1' 'libexpat>=2.8.5-r0' 'pcre2>=10.49-r0' 'tiff>=4.7.2-r0'
COPY nginx.conf /etc/nginx/nginx.conf
COPY keyorix-backend.conf /etc/nginx/keyorix-backend.conf
# HSTS-behind-a-load-balancer policy: nginx-hsts.conf is the "no trusted proxy,
# no HSTS" default; docker-entrypoint.d/40-keyorix-hsts.sh regenerates it at start
# from KEYORIX_WEB_TRUSTED_PROXIES (see docs/SELF_HOSTING.md), so the directory
# must be writable by uid 101.
COPY nginx-hsts.conf /etc/nginx/keyorix/nginx-hsts.conf
COPY --chmod=0755 docker-entrypoint.d/40-keyorix-hsts.sh /docker-entrypoint.d/40-keyorix-hsts.sh
COPY --from=builder /app/dist /usr/share/nginx/html

# busybox wget ships in nginx:alpine; curl does not. 127.0.0.1, not localhost:
# Alpine's musl resolver tries ::1 (IPv6) first for "localhost", and nginx
# below only listens on 0.0.0.0 (IPv4) — verified this healthcheck has always
# failed with "Connection refused" for that reason, pre-existing and
# independent of the non-root change below (reproduced against the original
# root-running image too).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["sh", "-c", "wget -q --spider http://127.0.0.1/health || exit 1"]

# Run as nginx:alpine's own built-in non-root user (uid 101) rather than root.
# The Helm deployment (deploy/helm/keyorix/templates/web-deployment.yaml)
# already assumed this — it sets runAsUser: 101 and grants
# CAP_NET_BIND_SERVICE so nginx can still bind port 80 as non-root — but that
# Kubernetes securityContext only applies under the Helm chart; plain
# `docker run`/`docker compose` had no such override, so the container ran as
# root there. This makes non-root the image's own default across every
# deployment path, matching what the chart already assumed.
#
# The base image's /var/cache/nginx, /var/log/nginx, and /run are root-owned
# (verified: nginx fails at startup with "mkdir /var/cache/nginx/client_temp:
# Permission denied" without this) — nginx's master process creates its
# temp/cache subdirs and pid file at startup, and our nginx.conf writes real
# log files under /var/log/nginx rather than the base image's default
# symlink-to-stdout/stderr setup, so both need to be writable by uid 101
# before dropping to it.
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /run /etc/nginx/keyorix
USER 101

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
