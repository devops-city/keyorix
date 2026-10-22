### Internal
- **gRPC machine-identity `project_id` narrowing no longer goes through `int`.** `machineIdentityToProto` now uses `uintToU32` like the other model-ID call sites, which clears CodeQL `go/incorrect-integer-conversion` (alert 1268). Values are unchanged; an out-of-range ID still saturates to 0.
