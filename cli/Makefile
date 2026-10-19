# cli/Makefile -- the thin CLI's own module (ADR-108). Deliberately separate from the root
# Makefile, matching operator/'s precedent (a separate module gets its own build tooling).

OAPI_CODEGEN_VERSION=v2.4.1
FILTERED_SPEC=$(CURDIR)/.openapi-filtered.yaml

# This module is deliberately excluded from the repo's root go.work (matching operator/'s
# precedent -- see .github/workflows/ci.yml's `cli` job). Without this, `go` auto-detects
# that go.work when invoked from a subdirectory of the repo and resolves patterns against
# the ROOT module instead of this one.
export GOWORK=off

.PHONY: build test client-deps client

build:
	go build -o bin/keyorix .

test:
	go test ./...

client-deps:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)

# Regenerate internal/apiclient/{types,client}.gen.go from the server's
# server/http/handlers/openapi.yaml, narrowed to the paths this module actually calls
# (internal/apiclient/gen/filterspec.go's keptPaths list -- extend it there as later Phase 3
# PRs wire more command groups, per docs/cli-split-inventory.md §7). Runs proto-deps'-
# equivalent (client-deps) first so a fresh checkout works; needs the Go bin dir on PATH.
client: client-deps
	go run ./internal/apiclient/gen ../server/http/handlers/openapi.yaml $(FILTERED_SPEC)
	PATH="$$(go env GOPATH)/bin:$$PATH" oapi-codegen -generate types -package apiclient -o internal/apiclient/types.gen.go $(FILTERED_SPEC)
	PATH="$$(go env GOPATH)/bin:$$PATH" oapi-codegen -generate client -package apiclient -o internal/apiclient/client.gen.go $(FILTERED_SPEC)
	rm -f $(FILTERED_SPEC)

.PHONY: docs

# Regenerate docs/cli-reference.md and docs/man/keyorix.1 from the command tree. cli/cmd's
# TestCLIReferenceIsFresh fails when they are stale, so run this after changing any command,
# flag, example or help text.
docs:
	mkdir -p ../docs/man
	go run . docs markdown > ../docs/cli-reference.md
	go run . docs man > ../docs/man/keyorix.1
