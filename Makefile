BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
# The Vault/OpenBao migration tool (migrate/, ADR-108 "moved out, not dropped").
# A separate Go module with its own release cadence -- see migrate/Makefile's
# own header for why it isn't folded into keyorix-server or the CLI.
BINARY_MIGRATE=keyorix-migrate
# AIR-GAPPED release variant (-tags noaws,noazure,nogcp — ADR-109 step 6):
# drops every AWS/Azure/GCP SDK package from the binary (measured 0 remaining,
# scripts/airgap-dependency-guard.sh enforces this). Vault and Kubernetes STAY
# (ADR-109's open-questions decision: on-prem Vault read-through and on-prem
# k8s are legitimate air-gapped uses). Linux only, same as the release variant
# it replaces (B3/S4 decision, see the release-notes line in RELEASING.md):
# `keyorix-server-lean` (-tags lean, a much narrower exclusion — only
# rotation/awsiam + evidencesink/objectstore, still 131 cloud SDK packages
# per the ADR109-AIRGAP track's own 2026-09-27 measurement) is REMOVED from
# `make release`/`make sbom`, not aliased — the two tags have never excluded
# the same set of packages, so treating one as a synonym for the other would
# misrepresent what the "lean" name has actually meant to anyone relying on
# it. `-tags lean` itself (internal/rotation/awsiam_lean.go,
# internal/evidencesink/objectstore_lean.go) is untouched in Go source — only
# the release/SBOM/publish surface changes here.
BINARY_SERVER_AIRGAP=$(BINARY_SERVER)-airgap
BUILD_DIR=./bin
VERSION?=dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Air-gap trust keys (ADR-062): embed the trusted update/license signing PUBLIC keys at
# build time, each "keyID=base64pub". Empty by default → a dev build trusts no keys and
# verification fails closed; release builds set these. `keyorix trust keygen` prints the
# exact value to use.
TRUST_UPDATE_KEYS?=
TRUST_LICENSE_KEYS?=
# Inject the build identity into keyorix-server plus the shared internal/version package
# (read by the server's /health + /system/info). Commit is deterministic per source
# revision, so release builds stay reproducible (no build date).
VERSION_LDFLAGS=-X github.com/keyorixhq/keyorix/internal/version.Version=$(VERSION) -X github.com/keyorixhq/keyorix/internal/version.Commit=$(GIT_COMMIT) -X github.com/keyorixhq/keyorix/pkg/trust.updateKeysB64=$(TRUST_UPDATE_KEYS) -X github.com/keyorixhq/keyorix/pkg/trust.licenseKeysB64=$(TRUST_LICENSE_KEYS)
LDFLAGS=-ldflags "$(VERSION_LDFLAGS)"
# RELEASE_LDFLAGS additionally strips the symbol table + DWARF debug info (-s -w):
# ~92MB -> ~62MB for keyorix-server. Only the `release` target uses this — build-cli/
# build-server/build-ui/dev keep full symbols (plain LDFLAGS) for local debugging.
# Stripping does NOT remove pclntab, so panic stack traces still show function names;
# only an attached debugger (dlv) loses symbols, an acceptable release-binary tradeoff.
RELEASE_LDFLAGS=-ldflags "-s -w $(VERSION_LDFLAGS)"
# The new CLI (cli/) is a separate Go module (ADR-108 Decision A) with its own build
# identity package, cli/internal/cliversion -- it cannot see internal/cli.version or
# internal/version, and must not: importing either would violate the no-server-deps
# guarantee cli/internal/depguard enforces. No commit/trust keys: the thin CLI has no
# air-gap update/license verification surface of its own.
CLI_VERSION_LDFLAGS=-X github.com/keyorixhq/keyorix/cli/internal/cliversion.Version=$(VERSION)
CLI_LDFLAGS=-ldflags "$(CLI_VERSION_LDFLAGS)"
CLI_RELEASE_LDFLAGS=-ldflags "-s -w $(CLI_VERSION_LDFLAGS)"
# migrate/ (keyorix-migrate) is likewise its own Go module (ADR-108) with its own build
# identity package, migrate/internal/migrateversion -- same isolation rule as the CLI.
MIGRATE_VERSION_LDFLAGS=-X github.com/keyorixhq/keyorix/migrate/internal/migrateversion.Version=$(VERSION)
MIGRATE_RELEASE_LDFLAGS=-ldflags "-s -w $(MIGRATE_VERSION_LDFLAGS)"

.PHONY: build build-cli build-server build-server-airgap airgap-dependency-guard build-ui populate-webui-dist install install-cli install-server clean run db-up dev docker-build docker-up docker-down docker-logs proto proto-deps proto-lint release sbom _sbom-generate smoke check-release-assets airgap-e2e k8s-e2e demo-check

# Pinned protoc-gen plugin versions (match google.golang.org/{protobuf,grpc} in go.mod).
PROTOC_GEN_GO_VERSION=v1.36.11
PROTOC_GEN_GO_GRPC_VERSION=v1.6.2

# Install the protoc-gen-go / protoc-gen-go-grpc plugins buf invokes. buf itself
# must be installed separately (`brew install bufbuild/buf/buf`).
proto-deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto-lint:
	buf lint

# Regenerate server/proto/pb/*.pb.go from server/proto/keyorix.proto. Runs
# proto-deps first so a fresh checkout works; needs the Go bin dir on PATH.
#
# The rm is what buf.gen.yaml's `clean:` used to do, narrowed to the files
# this target actually owns. buf's own clean wipes the whole output directory,
# which meant every `make proto` deleted server/proto/pb/generated_code_test.go
# -- the hand-written guard asserting this package contains only generated
# code. See buf.gen.yaml for the full note.
proto: proto-deps
	rm -f server/proto/pb/*.pb.go
	PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

build: build-cli build-server

# The new, thin CLI (cli/) is a separate Go module excluded from the repo's root
# go.work (matching operator/'s precedent -- see cli/Makefile's own header), so
# building it from here requires cd'ing in with GOWORK=off, same as every other
# cli/-targeting recipe below (release, _sbom-generate).
build-cli:
	(cd cli && GOWORK=off go build $(CLI_LDFLAGS) -o $(CURDIR)/$(BUILD_DIR)/$(BINARY_CLI) .)

build-server:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server

# build-server-airgap: local dev build of the AIR-GAPPED profile (ADR-109 step
# 6, B2/S3). Not cross-compiled or stripped here — see `release`'s
# BINARY_SERVER_AIRGAP cross-compiles for the actual shipped artifact (B3/S4).
build-server-airgap:
	go build -tags noaws,noazure,nogcp $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER_AIRGAP) ./server

# airgap-dependency-guard: fails the build if the air-gapped profile links a
# forbidden cloud-SDK package (ADR-109 step 6, B2/S3). See the script's own
# header for the full allowlist mechanism.
airgap-dependency-guard:
	./scripts/airgap-dependency-guard.sh

# populate-webui-dist: builds the dashboard (web/, now an in-repo subtree —
# ADR-070) and copies the real output into server/webui/dist/, which is
# gitignored except the committed placeholder index.html. Does NOT restore
# that placeholder — shared by build-ui and release below, which each need
# the real dist/ present for one or more `go build`s (embed.go's
# `//go:embed all:dist` bakes in whatever is physically on disk at compile
# time) and each restore the placeholder themselves, exactly once, after
# their own last build that needs the real thing. Restoring here instead
# would run in the middle of release's 10 cross-compiles (Make prerequisites
# complete in full before the depending target's own recipe starts), leaving
# every one of them with a placeholder index.html paired with the real
# hashed JS/CSS bundles copied in below -- a broken, inconsistent embed.
populate-webui-dist:
	@command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI"; exit 1; }
	cd web && pnpm install --frozen-lockfile && pnpm build
	rm -rf server/webui/dist
	mkdir -p server/webui/dist
	cp -R web/dist/. server/webui/dist/

# build-ui: build the web dashboard and embed it into a native server binary,
# so a single keyorix-server serves both API and UI (air-gap "one file"
# deploy). Requires pnpm. The committed placeholder is restored afterward so
# the working tree stays clean — the binary already has the real UI embedded
# regardless of what's on disk after this returns.
build-ui: populate-webui-dist
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server
	@git checkout -- server/webui/dist/index.html 2>/dev/null || true
	@echo "Built $(BUILD_DIR)/$(BINARY_SERVER) with the web UI embedded."

install-cli: build-cli
	sudo mv $(BUILD_DIR)/$(BINARY_CLI) /usr/local/bin/$(BINARY_CLI)

install-server: build-server
	sudo mv $(BUILD_DIR)/$(BINARY_SERVER) /usr/local/bin/$(BINARY_SERVER)

install: install-cli install-server

# Run the server locally against the docker-compose Postgres, using the
# committed dev config. `db-up` ensures Postgres is running first.
run: db-up
	KEYORIX_CONFIG_PATH=configs/dev.yaml KEYORIX_DB_PASSWORD=keyorix123 KEYORIX_MASTER_PASSWORD=keyorix123 go run ./server

# Start only the Postgres service (not the full stack — `make run` runs the
# server on :8080 itself, so we don't want the compose server container too).
db-up:
	docker compose up -d postgres

dev: install-cli
	@echo "✓ keyorix CLI installed to /usr/local/bin"
	@echo "✓ Start server with: make run"

# Cross-compile the published release artifacts. Asset names use the
# {binary}_{os}_{arch} convention that install.sh downloads and that the GitHub
# releases already use — keep these three in sync. Consumed by
# .github/workflows/release.yml on a vX.Y.Z tag.
#
# Depends on populate-webui-dist, not build-ui: build-ui's own recipe ends by
# restoring server/webui/dist/index.html to the committed placeholder, and
# Make prerequisites run to completion before this recipe starts — depending
# on build-ui here would mean every one of the 10 `go build`s below embeds a
# placeholder index.html alongside the real hashed JS/CSS bundles
# populate-webui-dist copies in, since nothing would rebuild dist/ in
# between. The 6 server-family builds (4 full + 2 air-gapped) are the ones that
# actually embed it (server/webui/embed.go), but populating once up front is
# simplest and harmless for the 4 CLI builds. The placeholder is restored
# once, at the very end, after every build that needs the real dist/ has
# already run.
release: populate-webui-dist
	@echo "→ Cross-compiling $(VERSION)"
	@mkdir -p dist
	(cd cli && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_linux_amd64    .)
	(cd cli && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_linux_arm64    .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_darwin_amd64   .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_darwin_arm64   .)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_amd64  ./server
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_arm64  ./server
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_amd64 ./server
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_arm64 ./server
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -tags noaws,noazure,nogcp $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER_AIRGAP)_linux_amd64 ./server
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -tags noaws,noazure,nogcp $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER_AIRGAP)_linux_arm64 ./server
	(cd migrate && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(MIGRATE_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_MIGRATE)_linux_amd64  .)
	(cd migrate && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(MIGRATE_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_MIGRATE)_linux_arm64  .)
	(cd migrate && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(MIGRATE_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_MIGRATE)_darwin_amd64 .)
	(cd migrate && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(MIGRATE_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_MIGRATE)_darwin_arm64 .)
	$(MAKE) _sbom-generate
	@cd dist && (sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt)
	@git checkout -- server/webui/dist/index.html 2>/dev/null || true
	@echo "✅ Release binaries + SBOMs in dist/"

# CycloneDX SBOM per shipped binary (app mode: exactly the deps linked into that
# binary + Go stdlib) plus one production-only frontend SBOM linked from each
# server binary's SBOM (ADR-073 — before that ADR, this covered the Go module
# graph only, which stopped being a complete description of keyorix-server the
# moment server/webui/embed.go started baking the built dashboard in). Feed to
# govulncheck/grype to answer "are we affected by CVE-X?" — the core CRA
# Article 14 question. Requires cyclonedx-gomod on PATH
# (go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0)
# and cdxgen on PATH (npm ci --ignore-scripts, then add
# node_modules/.bin to PATH — see package.json).
sbom:
	@mkdir -p dist
	$(MAKE) _sbom-generate
	@echo "✅ SBOMs in dist/"

# Shared by release and sbom so the two targets can't silently drift (ADR-073).
# Order matters and is enforced by this sequencing, not left to convention:
# the frontend SBOM must exist in its final form, hashed, before any server
# Go SBOM is generated and linked to it — generating them the other way
# round would leave a reference that validates cleanly while pointing at a
# stale or absent hash. See scripts/link-sbom.mjs's own header.
_sbom-generate:
	@echo "→ Generating frontend SBOM (ADR-073), production scope only"
	# cdxgen must run with NO --type flag here. `--type npm` silently drops to
	# scanning package.json's direct dependencies only (47 components instead
	# of the real ~478-package pnpm-lock.yaml graph filtered to ~125
	# production) — no error, just wrong. See
	# web/scripts/build-frontend-sbom.mjs's own header for the full story
	# (this exact trap, measured, is why the flag is absent below).
	cd web && node scripts/build-frontend-sbom.mjs ../dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	@echo "→ Generating per-binary Go CycloneDX SBOMs (one per binary, not per binary family)"
	# cli/go.mod replaces github.com/keyorixhq/keyorix with ../ (ADR-108 thin CLI), so
	# cyclonedx-gomod hashes the whole repo directory as a local module. pnpm's
	# web/node_modules holds symlinks to directories, which that hash cannot read
	# ("is a directory"), so the v0.95.0 release job failed here. The frontend SBOM
	# above is already written, so web/node_modules is moved aside for these four
	# commands and always restored (trap), including on failure.
	@set -e; aside="$(abspath $(CURDIR)/..)/.keyorix-sbom-web-node_modules.$$$$"; \
	if [ -d web/node_modules ]; then mv web/node_modules "$$aside"; trap 'mv "'"$$aside"'" web/node_modules' EXIT; fi; \
	(cd cli && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_linux_amd64_sbom.cdx.json    .); \
	(cd cli && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_linux_arm64_sbom.cdx.json    .); \
	(cd cli && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_darwin_amd64_sbom.cdx.json   .); \
	(cd cli && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_darwin_arm64_sbom.cdx.json   .);
	@echo "→ Generating per-binary Go CycloneDX SBOMs for keyorix-migrate"
	# Unlike cli/go.mod, migrate/go.mod carries no local `replace ... => ../`
	# directive (it's a full sibling module, not a dependency-pruned leaf --
	# docs/design-keyorix-migrate.md) -- cyclonedx-gomod never leaves migrate/
	# to hash the repo, so the web/node_modules workaround above does not apply here.
	(cd migrate && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_MIGRATE)_linux_amd64_sbom.cdx.json    .)
	(cd migrate && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_MIGRATE)_linux_arm64_sbom.cdx.json    .)
	(cd migrate && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_MIGRATE)_darwin_amd64_sbom.cdx.json   .)
	(cd migrate && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_MIGRATE)_darwin_arm64_sbom.cdx.json   .)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json  .
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json  .
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json .
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json .
	@echo "→ Generating per-binary Go CycloneDX SBOMs for the air-gapped release variant"
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-tags=noaws,noazure,nogcp cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER_AIRGAP)_linux_amd64_sbom.cdx.json .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOFLAGS=-tags=noaws,noazure,nogcp cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER_AIRGAP)_linux_arm64_sbom.cdx.json .
	@echo "→ Linking frontend SBOM into the six server Go SBOMs (ADR-073)"
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json  dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json  dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER_AIRGAP)_linux_amd64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER_AIRGAP)_linux_arm64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	@echo "→ Verifying frontend SBOM hash matches all six server SBOM links (ADR-073 decision #5)"
	node scripts/verify-sbom-links.mjs \
		dist/$(BINARY_SERVER)_frontend_sbom.cdx.json \
		dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json \
		dist/$(BINARY_SERVER_AIRGAP)_linux_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER_AIRGAP)_linux_arm64_sbom.cdx.json

# smoke: the CI + release gate for the SHIPPED $(BINARY_CLI) binary (Phase 5, ADR-108).
# Executes the documented QUICK_START.md flow -- keyorix-server admin init, start the
# server, keyorix login, project create, secret create/get, secret export -- step for
# step against a freshly built binary. See scripts/smoke.sh's own header for the exact
# correspondence to QUICK_START.md.
smoke: build-cli build-server
	@./scripts/smoke.sh

# airgap-e2e: MANUAL target only, not run in CI (needs Docker/Podman, spins up
# real containers, takes tens of seconds waiting out a real audit-checkpoint
# interval) -- see scripts/airgap-e2e.sh's own header for the full flow and
# why CI's unit/integration/fuzz layer (server/admin/backup_restore_*_test.go)
# isn't a substitute for it.
airgap-e2e:
	@./scripts/airgap-e2e.sh

# demo-check: "will the demo work?" in about 5 minutes -- brings up (or
# checks, with DEMO_CHECK_ARGS="--url ...") the demo golden path
# (docs/demo/GOLDEN-PATH.md) end to end through the public API/CLI only, one
# ✅/❌ line per step. See scripts/demo/check.sh's own header for every flag
# (--sqlite/--postgres, --keep, --ui, --offline).
demo-check:
	@./scripts/demo/check.sh $(DEMO_CHECK_ARGS)

# e2e-smoke: SESSION-I's fresh-install FEATURE smoke, distinct from `smoke`
# above -- that target proves the QUICK_START.md happy path (project/secret/
# share/machine, one CRUD each) on the SHIPPED CLI binary; this one proves
# every route in scripts/e2e/routes.json (I1) is reachable, with no 5xx
# anywhere, on a genuinely freshly-`admin migrate`d database, real server,
# real HTTP -- the class of gap PR #2258 found (7 shipped features 500ing
# with "no such table" on fresh install because no test ever exercised them
# against a really-empty database). Build-tag e2e, excluded from `make test`/
# `go test ./...`'s default inner loop -- see scripts/e2e's own package doc.
# SQLite only; add KEYORIX_TEST_PG_DSN for the PostgreSQL leg too (see
# e2e-smoke-postgres below for the docker incantation).
e2e-smoke:
	go test -tags e2e ./scripts/e2e/... -run TestAPISmoke_SQLite -v -timeout 300s

# e2e-smoke-postgres: same, against a real PostgreSQL backend. Requires
# docker and KEYORIX_TEST_PG_DSN pointed at it:
#   docker run -d --name keyorix-e2e-pg -e POSTGRES_PASSWORD=keyorix-e2e \
#     -e POSTGRES_DB=keyorix -e POSTGRES_USER=keyorix -p 15432:5432 postgres:16
#   KEYORIX_TEST_PG_DSN="host=localhost user=keyorix password=keyorix-e2e dbname=keyorix port=15432 sslmode=disable" \
#     make e2e-smoke-postgres
e2e-smoke-postgres:
	@if [ -z "$$KEYORIX_TEST_PG_DSN" ]; then \
		echo "KEYORIX_TEST_PG_DSN is not set -- see this target's own comment in the Makefile for the docker incantation" >&2; \
		exit 1; \
	fi
	go test -tags e2e ./scripts/e2e/... -run TestAPISmoke_Postgres -v -timeout 300s

# e2e-smoke-upgrade: I3 -- downloads the previous release's server binary,
# provisions a database with it, then migrates and boots that SAME database
# with the binary just built from HEAD (an in-place upgrade, exactly like a
# real operator's stop/migrate/start), and re-runs the full smoke sweep
# against it -- catches "table missing on an upgraded install" as well as a
# fresh one. Requires network access to GitHub's release-asset URLs; skips
# (not fails) if that's unavailable, or if no release binary is published
# for this GOOS/GOARCH. Override the release it upgrades FROM with
# KEYORIX_E2E_UPGRADE_FROM_TAG (defaults to the immediately-prior release).
e2e-smoke-upgrade:
	go test -tags e2e ./scripts/e2e/... -run TestAPISmoke_UpgradePath -v -timeout 300s

# e2e-web-smoke: I4 -- the same fresh-install premise, driving the real web
# UI (not the API directly) against a real backend with Playwright. See
# scripts/e2e/web-real-smoke.sh's own header for the full boot sequence.
# Requires pnpm; Playwright browsers must already be installed
# (`cd web && pnpm exec playwright install` once, if scripts/e2e/
# web-real-smoke.sh's own run reports a missing-executable error).
e2e-web-smoke:
	@./scripts/e2e/web-real-smoke.sh

# e2e-smoke-all: everything above in one run -- SQLite, the upgrade path,
# and the web UI (NOT the Postgres leg, which needs a docker container the
# other three don't -- run e2e-smoke-postgres separately once one is up).
e2e-smoke-all: e2e-smoke e2e-smoke-upgrade e2e-web-smoke

# e2e-journeys: SESSION-N's customer-journey E2E -- N1-N3 and N6 (disaster
# recovery needs no containers, so it's plain `e2e`-tagged and runs here
# too), distinct from e2e-smoke above. scripts/e2e's own smoke driver
# asserts "no 5xx anywhere"; these assert the RESULT of a realistic
# end-to-end scenario (read-back values, exact audit event counts, denial
# status codes) through the real keyorix-server binary and keyorix CLI, on
# a freshly bootstrapped install. SQLite only, no Docker -- fast enough for
# the merge-queue tier (each journey ~6-19s; ~35-40s combined, measured
# live). Build tag e2e (same as e2e-smoke) plus the shared
# scripts/e2e/harness package -- see docs/TESTING_GUIDE.md's "Customer
# journeys" section for the full picture, including N4/N5 below.
e2e-journeys:
	go test -tags e2e ./scripts/e2e/journeys/... -v -timeout 300s

# e2e-journeys-containers: N4-N6 -- migrate from Vault/OpenBao, SSO login via
# a real Keycloak, and disaster recovery (backup/restore/KEK rotation) --
# plus journey7 (R4 spec #1: dynamic-secret full lifecycle against a real
# Postgres target). Needs BOTH the e2e and e2e_containers build tags:
# N4/N5/journey7 are gated on `e2e && e2e_containers`, so `make e2e-journeys`
# (`-tags e2e`) never builds or runs them, whether or not the runner has
# Docker. All need Docker (skip cleanly if absent, UNLESS
# KEYORIX_E2E_CONTAINERS is set -- see journey4/5/7's own doc comments); N6 is
# plain SQLite, no containers. Nightly tier -- Keycloak's own startup
# dominates N5's runtime (measured 16-56s across runs); N4 and N6 are each
# ~13-19s, journey7 ~15s. ~65-105s combined, measured live.
e2e-journeys-containers:
	KEYORIX_E2E_CONTAINERS=1 go test -tags e2e,e2e_containers ./scripts/e2e/journeys/... -run 'TestJourney_(VaultMigrate|SSOLogin|DisasterRecovery|DynamicSecretLifecycle)' -v -timeout 600s

# k8s-e2e: MANUAL target only, not run in CI by default (needs Docker + kind,
# builds 4 images, installs a real External Secrets Operator, takes several
# minutes) -- see scripts/k8s-e2e/run.sh's own header for the full flow.
# Proves the Helm chart, operator, and keyorix-k8s-sync agent actually work
# against a real cluster, not just that they render correctly -- `helm lint`/
# `helm template`/kubeconform (already run in CI) catch none of the four real
# bugs Session J found this way (see the script's own header).
k8s-e2e:
	@./scripts/k8s-e2e/run.sh


clean:
	rm -rf $(BUILD_DIR) dist/

docker-build:
	docker build -f server/Dockerfile -t keyorix-server .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f keyorix
vet:
	go vet ./...
lint:
	golangci-lint run ./...
# Same command as ci.yml's openapi-lint job (vacuum, version pinned in devtools/vacuum/go.mod).
.PHONY: openapi-lint
openapi-lint:
	GOWORK=off GOFLAGS=-mod=readonly go tool -modfile=devtools/vacuum/go.mod vacuum lint -r .vacuum.yaml --no-update-check server/http/handlers/openapi.yaml
test:
	go test -race ./...
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
security:
	govulncheck ./...
	gosec ./...
ci: vet test security build
