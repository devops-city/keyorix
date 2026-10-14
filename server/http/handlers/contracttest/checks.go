package contracttest

import (
	"flag"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// allOperationIDs returns every operationId declared in the spec.
func allOperationIDs() []string {
	var ids []string
	for _, pathItem := range spec.Paths.Map() {
		for _, op := range pathItem.Operations() {
			if op.OperationID != "" {
				ids = append(ids, op.OperationID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// operationsWithoutID identifies each spec operation that has no
// operationId, as "METHOD path" since it has nothing else to name it by.
// Every function above that walks the spec by operationId silently drops
// these -- they can never be registered in pendingRegistry or
// outOfScopeRegistry, never enforced, and never flagged by CheckPartition's
// main loop below, which only ever iterates allOperationIDs(). This exists
// so that omission fails loudly instead of leaving the operation invisible
// to the entire harness.
func operationsWithoutID() []string {
	var missing []string
	for path, pathItem := range spec.Paths.Map() {
		for method, op := range pathItem.Operations() {
			if op.OperationID == "" {
				missing = append(missing, fmt.Sprintf("%s %s", method, path))
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// operationsWithSchema returns the set of operationIds that declare at least
// one 2xx response with a JSON-Schema-bearing content block, for any content
// type. This is deliberately the same "has a schema at all" test used in
// ADR-074's Phase 0 count (10 operations) -- it does not distinguish a real
// application/json schema from a near-content-free `{type: string, format:
// binary}` one. That distinction is a registry/enforcement concern (see
// registry.go), not a spec-shape concern.
func operationsWithSchema() map[string]bool {
	result := map[string]bool{}
	for _, pathItem := range spec.Paths.Map() {
		for _, op := range pathItem.Operations() {
			if op.OperationID != "" && operationHasSchema(op) {
				result[op.OperationID] = true
			}
		}
	}
	return result
}

// operationHasSchema reports whether op declares at least one non-204 2xx
// response with a JSON-Schema-bearing content block, for any content type.
func operationHasSchema(op *openapi3.Operation) bool {
	if op.Responses == nil {
		return false
	}
	for status, responseRef := range op.Responses.Map() {
		if !is2xxExceptNoContent(status) || responseRef.Value == nil {
			continue
		}
		if responseHasSchema(responseRef.Value) {
			return true
		}
	}
	return false
}

func is2xxExceptNoContent(status string) bool {
	return len(status) > 0 && status[0] == '2' && status != "204"
}

func responseHasSchema(resp *openapi3.Response) bool {
	for _, mediaType := range resp.Content {
		if mediaType.Schema != nil {
			return true
		}
	}
	return false
}

// CheckPartition asserts that every operation in the spec lands in exactly
// one of: enforced (has a schema, not registered out-of-scope),
// pending-with-reason, or out-of-scope-with-reason. Both failure directions
// are checked -- see ADR-074, "Fail-closed semantics" -- and so is the
// reverse direction: every registry entry (pendingRegistry,
// outOfScopeRegistry, exercisingTests) must still name a real, current
// operationId, so a renamed or deleted operation can't leave a stale entry
// behind forever.
func CheckPartition() error {
	loadSpec()
	if specErr != nil {
		return specErr
	}

	ids := allOperationIDs()
	validIDs := map[string]bool{}
	for _, opID := range ids {
		validIDs[opID] = true
	}

	withSchema := operationsWithSchema()
	var violations []string

	for _, opID := range ids {
		hasSchema := withSchema[opID]
		pendingReason, isPending := pendingRegistry[opID]
		outOfScopeReason, isOutOfScope := outOfScopeRegistry[opID]

		switch {
		case isPending && isOutOfScope:
			violations = append(violations, fmt.Sprintf(
				"%s: registered in BOTH pendingRegistry (%q) and outOfScopeRegistry (%q) -- pick one",
				opID, pendingReason, outOfScopeReason,
			))
		case isPending && hasSchema:
			violations = append(violations, fmt.Sprintf(
				"%s: has a 2xx schema in openapi.yaml but is still in pendingRegistry (%q) -- "+
					"remove the pending entry, it is now enforced",
				opID, pendingReason,
			))
		case isOutOfScope && hasSchema && !schemaExemptOperations[opID]:
			violations = append(violations, fmt.Sprintf(
				"%s: has a 2xx schema in openapi.yaml but is registered in outOfScopeRegistry (%q) "+
					"without being in schemaExemptOperations (registry.go) -- a schema-bearing "+
					"operation can't be silently opted out of enforcement this way; either wire it "+
					"up as enforced, or add it to schemaExemptOperations with justification if it "+
					"genuinely has no generated-client use case",
				opID, outOfScopeReason,
			))
		case !hasSchema && !isPending && !isOutOfScope:
			violations = append(violations, fmt.Sprintf(
				"%s: has no 2xx schema in openapi.yaml and is not registered in pendingRegistry "+
					"or outOfScopeRegistry -- add an entry to one of them in registry.go",
				opID,
			))
		}
	}

	for _, methodAndPath := range operationsWithoutID() {
		violations = append(violations, fmt.Sprintf(
			"%s: operation has no operationId -- every operation must declare one so it can be "+
				"tracked by this harness (pendingRegistry/outOfScopeRegistry/enforced), otherwise "+
				"it is invisible to every check in this package",
			methodAndPath,
		))
	}

	violations = append(violations, staleRegistryEntries("pendingRegistry", pendingRegistryKeys(), validIDs)...)
	violations = append(violations, staleRegistryEntries("outOfScopeRegistry", outOfScopeRegistryKeys(), validIDs)...)
	violations = append(violations, staleRegistryEntries("exercisingTests", exercisingTestsKeys(), validIDs)...)

	if len(violations) == 0 {
		return nil
	}
	sort.Strings(violations)
	return fmt.Errorf(
		"contracttest: openapi.yaml <-> registry partition is inconsistent (%d violation(s)):\n  - %s",
		len(violations), strings.Join(violations, "\n  - "),
	)
}

// staleRegistryEntries flags any key in a registry map that no longer names
// a real operationId in the spec -- e.g. left behind by a rename or removal
// that added a fresh entry under the new operationId without cleaning up
// the old one. registryName is used only to make the violation message
// point at the right map.
func staleRegistryEntries(registryName string, keys []string, validIDs map[string]bool) []string {
	var violations []string
	for _, opID := range keys {
		if !validIDs[opID] {
			violations = append(violations, fmt.Sprintf(
				"%s: registered in %s but no such operationId exists in openapi.yaml -- "+
					"stale entry, remove it (renamed or deleted operation?)",
				opID, registryName,
			))
		}
	}
	return violations
}

func pendingRegistryKeys() []string {
	keys := make([]string, 0, len(pendingRegistry))
	for opID := range pendingRegistry {
		keys = append(keys, opID)
	}
	return keys
}

func outOfScopeRegistryKeys() []string {
	keys := make([]string, 0, len(outOfScopeRegistry))
	for opID := range outOfScopeRegistry {
		keys = append(keys, opID)
	}
	return keys
}

func exercisingTestsKeys() []string {
	keys := make([]string, 0, len(exercisingTests))
	for opID := range exercisingTests {
		keys = append(keys, opID)
	}
	return keys
}

// enforcedOperationIDs is the set the coverage assertion checks against:
// every operation with a schema, minus anything explicitly opted out via
// outOfScopeRegistry (prometheusMetrics has a schema but is third-party
// code with no generated client -- see registry.go).
func enforcedOperationIDs() map[string]bool {
	enforced := map[string]bool{}
	for opID := range operationsWithSchema() {
		if _, outOfScope := outOfScopeRegistry[opID]; !outOfScope {
			enforced[opID] = true
		}
	}
	return enforced
}

// CheckAllEnforcedExercised asserts every enforced operation eligible to run
// in this invocation was exercised through AssertOpenAPIResponse. Called
// from TestMain after m.Run() returns, so it sees every test's result.
//
// "Eligible to run in this invocation" matters because server/http/handlers
// runs in CI as 4 separate `go test -run <shard-regexp>` processes
// (ci.yml's handlers-1..4 matrix legs, split by test-name hash) -- no CI job
// ever runs the package unsharded. A process-global completeness check would
// spuriously fail in 3 of every 4 shards, since any one exercising test
// lands in exactly one shard's process. To stay correct under that split
// without adding new CI wiring, this checks each enforced operation's known
// exercising test name(s) (exercisingTests, registry.go) against the
// CURRENT go test -run pattern -- the same regexp ci.yml already computed
// for this shard, read via the standard test.run flag. An operation whose
// exercising test isn't selected in this shard is skipped here, not failed
// (it will be checked when that test's shard runs); one whose test WAS
// eligible but still didn't record an exercise is a real failure.
//
// See ADR-074, "Coverage assertion: enforced must mean exercised".
//
// Returns nil immediately under `go test -list`: -list mode never actually
// invokes any Test function (m.Run() just prints matching names and
// returns), so every operation would trivially show as "never exercised" --
// not a real failure, just -list doing its job. Without this guard, a
// TestMain that calls this after m.Run() would make `go test -list` itself
// fail, which is exactly the command ci.yml runs to compute the handlers-1..4
// shards in the first place (`go test -list '^Test' ./server/http/handlers/...`).
func CheckAllEnforcedExercised() error {
	if testListModeActive() {
		return nil
	}

	loadSpec()
	if specErr != nil {
		return specErr
	}

	runFilter := currentRunFilter()
	enforced := enforcedOperationIDs()

	exercisedMu.Lock()
	defer exercisedMu.Unlock()

	var missing []string
	for opID := range enforced {
		if exercised[opID] {
			continue
		}
		names, known := exercisingTests[opID]
		if !known {
			missing = append(missing, fmt.Sprintf(
				"%s (no entry in exercisingTests -- add one in registry.go pointing at the "+
					"test that calls AssertOpenAPIResponse for it)", opID,
			))
			continue
		}
		if !anyEligible(runFilter, names) {
			continue // this operation's test(s) run in a different shard
		}
		missing = append(missing, fmt.Sprintf("%s (exercisingTests: %s)", opID, strings.Join(names, ", ")))
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"contracttest: %d enforced operation(s) have a schema and are not registered "+
			"out-of-scope, but were eligible to run in this test invocation and still were "+
			"never exercised through AssertOpenAPIResponse -- \"enforced\" must mean "+
			"\"exercised\", not just \"listed\": %s",
		len(missing), strings.Join(missing, "; "),
	)
}

// testListModeActive reports whether this process was invoked as
// `go test -list <pattern>`.
func testListModeActive() bool {
	f := flag.Lookup("test.list")
	return f != nil && f.Value.String() != ""
}

// currentRunFilter returns the current `go test -run` pattern, or nil if
// unset (a full, unfiltered run -- e.g. a developer running
// `go test ./server/http/handlers/...` locally, or contracttest's own
// package tests, which never shard).
func currentRunFilter() *regexp.Regexp {
	f := flag.Lookup("test.run")
	if f == nil {
		return nil
	}
	pattern := f.Value.String()
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// An unparseable -run would have already failed `go test` itself
		// before TestMain ran; treat defensively as "unfiltered" rather
		// than panic in a coverage check.
		return nil
	}
	return re
}

// anyEligible reports whether at least one of names would be selected by
// runFilter -- i.e. whether at least one of this operation's known
// exercising tests could have run in this invocation. A nil filter (no -run
// set) selects everything.
func anyEligible(runFilter *regexp.Regexp, names []string) bool {
	if runFilter == nil {
		return true
	}
	return slices.ContainsFunc(names, runFilter.MatchString)
}
