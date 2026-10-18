# Complexity metrics

Keyorix should stay easy to run and easy to understand as it grows. The two scripts in
`scripts/metrics/` put a number on how big and how demanding it has become, so each release
review can see the cost of what it adds, next to the ease-of-use measurements.

This page explains what is measured and how to run it. It deliberately contains no results:
numbers in a document go stale, and the script is the source of truth. Run it for the ref you
care about.

## Run it

```bash
# one row of metrics for a ref (default HEAD)
scripts/metrics/complexity.sh [--json | --tsv] [ref]

# two refs side by side, with deltas and every new user-facing item by name
scripts/metrics/complexity-diff.sh [--surface-only] [--fail-on-growth] A B
```

Both read git refs from the checkout the scripts live in; fetch tags first
(`git fetch origin --tags`). The ref is exported into a temporary directory and removed
afterwards, so your working tree is never touched.

Requirements: `go`, `git`, `curl`, `tar`, `awk`. The first run fills the Go module cache. The
npm numbers come from the committed lockfile; nothing is installed. A full run builds the
server and CLI several times and starts the server six times, so allow a few minutes per ref.
`--surface-only` skips the builds that are not needed to list the user-facing surface.

Progress goes to stderr; the result goes to stdout, so `--json` and `--tsv` are safe to pipe.

## What is measured

Each metric has a one-line definition in the header of `scripts/metrics/complexity.sh`; this is
the same list with the reasoning.

**Code.** Go lines in non-test and test files, Go packages (directories with Go code), non-test
Go files over 800 lines, TypeScript/TSX lines under `web/` (non-test and test), and shell lines
under `scripts/`. Generated files (a `Code generated ... DO NOT EDIT` header) and `testdata/`
are excluded, and so is `scripts/metrics/`, so the measuring tool does not count itself. Size
is a proxy for how much a maintainer has to hold in their head.

**Dependencies.** Direct and total Go modules (`go list -m all` over the root, `cli/` and
`migrate/` modules together) and direct and total npm packages for `web/`, read from
`pnpm-lock.yaml`. Every dependency is something to patch, audit and keep compatible.

**Artefacts.** Size of the server and CLI binaries, built for linux/amd64 with the flags of
`make release` (`CGO_ENABLED=0`, `-trimpath`, `-s -w`). The server is built without the real
web bundle (that needs `pnpm` and the network), so compare refs with each other, not with a
published release asset. The container image size is included only with `--image` and a working
Docker; otherwise the script says it was skipped.

**Startup.** On a fresh SQLite install in a temporary directory (`admin init`,
`admin encryption init`, `admin migrate`, the baseline config of that ref, loopback): the median of five starts from
process start to the first HTTP 200 on `/health`, and the peak resident memory of a server left
idle for ten seconds after it became healthy. These two depend on the machine; compare runs
from the same machine.

**User-facing surface.** Everything an operator or integrator can be asked to learn:

- config keys, found by walking the `Config` struct tree with reflection (not by hand), and how
  many of them have no default. A key counts as having a default when it is non-zero after
  loading an empty config or in the baseline config `admin init` writes. A default applied
  later, where the key is used, is invisible to this check, so the "no default" figure is an
  upper bound;
- environment variables read: first arguments of `os.Getenv`, `os.LookupEnv` and
  `secretenv.Lookup`, plus any whole-string `KEYORIX_*` literal in non-test code;
- CLI commands and flags of `keyorix`, and of `keyorix-server admin`, found by recursing
  through `--help` of a built binary, so what is counted is what a user can see (hidden
  commands and flags are not counted, nor are cobra's `help`, `completion`, `--help`, `--version`);
- HTTP API operations: path and method pairs in the OpenAPI spec;
- gRPC methods: `rpc` lines in the proto files;
- user-facing doc pages, by the same inclusion rule as the ease-of-use measurement: `README.md`,
  `docs/SELF_HOSTING*`, `docs/operator/`, `docs/operations/`, and guides and references, but not
  ADRs, findings, specs or security internals.

**Internal weight.** What the project carries to stay correct: static guard tests (Go tests
named `*Guard*`, `*Sweep*` or `*Completeness*`), fuzz targets, entries in the `server/faultops`
registries, and the number of ADRs. These are not a cost to users, but they are a cost to
whoever changes the code, and they should grow for a reason.

## Reading the diff

`complexity-diff.sh A B` prints the table with deltas, then a section that names every config
key, environment variable, CLI command or flag, admin command or flag, API operation and gRPC
method that B adds or removes relative to A. New config keys without a default are called out
again. A release review reads that section; adding to it should be a decision, not an accident.
`--fail-on-growth` turns "B adds anything user-facing" into a non-zero exit, for a gate.

## Known limits

- The counts are definitions, not judgements. A bigger number is not automatically worse; an
  unexplained one is.
- Environment variables read through a helper that builds the name at run time are not seen. The
  script reports how many reads it could not resolve.
- Startup and memory vary with the machine and its load.
- Metrics that depend on repository layout (the OpenAPI path, the proto directory, the
  `faultops` registry layout) report what exists at that ref; a layout change between two refs
  shows up as a change in the number, so check the layout before reading a large jump.

The helpers that do the structural walking live next to the scripts and have their own tests
(`scripts/metrics/cfgkeys`, `scripts/metrics/surfacewalk`), so a refactor of the config
struct or the CLI cannot silently change what is counted.
