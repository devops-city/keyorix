### Fixed
- **Server, CLI and `migrate` did not compile for 32-bit ARM (`linux/arm`).** Three untyped constants above 2^31 were used as `int`: the dynamic-secret TTL bound (`internal/core`), the bundle component size limit in the error message (`pkg/bundleverify`) and a project-id range check (`migrate`). The checks keep their meaning (on a 32-bit `int` the bound cannot be exceeded, so it is clamped to `MaxInt`; messages still print the real limit). Nothing changes on 64-bit targets.

### Testing
- **ARM cross-build.** `scripts/edge/cross-build.sh` builds every shipped component (server full and air-gapped, CLI, `migrate`, operator, `keyorix-k8s-sync`, `keyorix-mcp`) for `linux/arm64` and `linux/arm` (GOARM=7) with `CGO_ENABLED=0`; `deploy/edge/arm_build_test.go` keeps the three packages above compiling for those targets. Compile and link only: running on ARM is pending. The footprint budget gained `linux/arm` binary-size rows.
