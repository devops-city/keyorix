### Changed
- **Server builds use profile-guided optimisation.** `server/default.pgo` is a merged CPU profile of the server under the benchmark workload; `go build ./server` (Makefile, release and the server Dockerfile) applies it automatically. Refresh it each release with `scripts/pgo/refresh.sh` (`docs/pgo.md`).
