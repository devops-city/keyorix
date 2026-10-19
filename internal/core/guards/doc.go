// Package guards holds the source-scanning guard tests of internal/core: tests
// that read the repository's .go files (go/parser, go/packages, filepath.Walk,
// grep) and assert a structural property of the code.
//
// They live apart from internal/core because they need nothing from it. A test
// inside package core is compiled into core's test archive, and that archive
// embeds one wrapper per promoted method for every test double that embeds the
// 1,000-method storage.Storage interface (hundreds of MB per source state), so
// running a one-file scanner cost a full core test build. This package imports
// no mocks and no core types, so its test archive is a few MB, and preflight can
// run every static guard without compiling core's tests.
//
// Rules for a test in this package (TestGuardsPackageStaysLight enforces the
// first):
//   - it must not import github.com/keyorixhq/keyorix/internal/core (the
//     scanned package) or define a struct that embeds storage.Storage;
//   - scanned paths are relative to this directory (internal/core/guards), so
//     internal/core is "..", the repository root is "../../..";
//   - a test that needs core's types, mocks or its registry entry files
//     (registry_entries_test.go) stays in internal/core.
package guards
