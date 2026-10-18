package contracttest

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// specPath is resolved relative to this source file's own location (not the
// process's working directory, which varies with how `go test` is invoked)
// so it holds regardless of which package's test binary links this one in.
var specPath = func() string {
	return filepath.Join(srcpath.RepoRoot(), "server", "http", "handlers", "openapi.yaml")
}()

var (
	specOnce sync.Once
	spec     *openapi3.T
	router   routers.Router
	specErr  error
)

// loadSpec parses and validates openapi.yaml and builds the operation router,
// once per test binary. Every exported entry point calls this first.
func loadSpec() {
	specOnce.Do(func() {
		spec, router, specErr = loadSpecFrom(specPath)
	})
}

// loadSpecFrom does loadSpec's actual work against an arbitrary path, kept
// separate from the sync.Once-guarded package state so its error branches
// (a malformed spec, one that fails OpenAPI validation, or one the router
// can't be built from) are directly unit-testable without the Once
// preventing a second, differently-configured run within the same test
// binary.
func loadSpecFrom(path string) (*openapi3.T, routers.Router, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("contracttest: loading %s: %w", path, err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		return nil, nil, fmt.Errorf("contracttest: %s failed OpenAPI validation: %w", path, err)
	}
	r, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("contracttest: building operation router from %s: %w", path, err)
	}
	return doc, r, nil
}
