# Profile-guided optimisation for the server

`server/default.pgo` is a merged CPU profile of the server under the benchmark
workload. Go's `-pgo=auto` (the default since Go 1.21) applies a `default.pgo`
found in the main package's directory, so every build of `./server` uses it with
no flag: `make`, `make release`, `server/Dockerfile` and plain `go build ./server`.
See <https://go.dev/doc/pgo>.

## What it does and does not change

- It only changes how the compiler inlines and lays out hot code. Behaviour,
  the audit-before-disclosure ordering and every permission check are untouched.
- The same source plus the same `default.pgo` gives the same binary, so
  `-trimpath` release builds stay reproducible; the file is part of the
  source tree that the release provenance and SBOM already cover.
- Builds with `-tags noaws,noazure,nogcp` use the same profile; functions
  that are compiled out are simply absent from it.
- Other binaries (`cli`, `migrate`, operator, k8s-sync) do not have a profile:
  they are short-lived or not on the request path.

## When to refresh

Once per release, before tagging (step 3 in `RELEASING.md`), and after a change
that moves the hot path a lot (new middleware, storage layer changes). A stale
profile is not wrong, it just optimises yesterday's hot spots; Go tolerates
source drift.

## How to refresh

1. Build a profiling server from the commit you are releasing:
   `scripts/pgo/refresh.sh hook`, build the image (or `go build ./server`), then
   `scripts/pgo/refresh.sh unhook` so the listener file is never committed.
   Run it with `KEYORIX_PGO_CAPTURE=1`; it serves pprof on `:6060`.
2. Stand up the usual bench stack (Postgres, default mode) and drive these
   workloads, taking one 12 s capture about 3 s into each 20 s run:
   - W1 at c=10 and c=50
   - W2 at c=10 and c=50
   - a slice of admin/list traffic, if the kit has it

   ```sh
   scripts/pgo/refresh.sh capture http://127.0.0.1:6060 12 w1-c50.pprof
   ```
3. Merge them into the profile (this overwrites `server/default.pgo`):

   ```sh
   scripts/pgo/refresh.sh merge w1-c10.pprof w1-c50.pprof w2-c10.pprof w2-c50.pprof
   ```
4. Build once with `go build -pgo=off` and once without; run the unit tests,
   then A/B the two on the bench VM before committing the new profile.

Capture on the bench VM, not a loaded laptop. Profiling the binary built with the
current `default.pgo` is fine and is what Go recommends (the profile converges).
