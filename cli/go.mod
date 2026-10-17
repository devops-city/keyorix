module github.com/keyorixhq/keyorix/cli

go 1.27

require (
	github.com/keyorixhq/keyorix v0.0.0-00010101000000-000000000000
	github.com/oapi-codegen/runtime v1.7.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
)

// The main module's own go.mod pulls in every cloud SDK and internal/core's full graph, but
// Go's pruned module graph (go 1.17+) only loads packages actually imported below --
// cli/internal/depguard's own test walks `go list -deps` to prove that stays true. Only
// pkg/bundleverify, pkg/licenseverify, and pkg/trust (all public leaf packages with zero
// internal/core, internal/storage, internal/config, or cloud-SDK imports of their own) are
// ever imported from this module (FINISH-SPLIT step 2, docs/cli-split-inventory.md §7 PR
// 10) -- do NOT import anything else from the main module.
replace github.com/keyorixhq/keyorix => ../
