package ports

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
)

// This file is the shared half of the "no heavy third-party library in
// internal/core's production closure" guard (INV-CORE-no-heavy-third-party-deps,
// reports/SESSION-CORE-DECOUPLE-PLAN-1.md section 5). It lives in
// internal/core/ports, not internal/core, so it stays independent of where the
// source-scanning guards inside internal/core end up.
//
// ADR-109's coreIntegrationDeps guard only names internal/* integration packages;
// it says nothing about third-party libraries. A library that internal/core does
// not use can still ride in through a package core imports (cobra through
// internal/securefiles, yaml.v3 through internal/secrettemplate), and every
// dependent of core then recompiles it.
//
// forbiddenHeavyDeps is declared EMPTY on purpose. Each decoupling cut adds its
// prefixes from its own heavy_deps_<cut>_test.go via registerForbiddenHeavyDep in
// init(), so two cuts never edit the same file (CLAUDE.md, "Test registry tables").
// A prefix ending in "/" matches every package below it; any other prefix matches
// the package itself and everything below it.
var forbiddenHeavyDeps = map[string]string{}

// registerForbiddenHeavyDep adds one forbidden prefix with the reason (the cut that
// removed it). It panics on a duplicate so two files cannot silently shadow each
// other.
func registerForbiddenHeavyDep(prefix, reason string) {
	if prefix == "" || reason == "" {
		panic("ports: registerForbiddenHeavyDep needs a prefix and a reason")
	}
	if prev, dup := forbiddenHeavyDeps[prefix]; dup {
		panic(fmt.Sprintf("ports: forbidden heavy dep %q registered twice (%q and %q)", prefix, prev, reason))
	}
	forbiddenHeavyDeps[prefix] = reason
}

// stillAllowedHeavy is the exact list of heavy (more than 1 MB of compiled
// archive) third-party libraries internal/core's production closure may still
// contain. kept: models needs it, see ask core-decouple-gorm-models-split.
//
// The comparison is exact in the way coreIntegrationDeps is: TestStillAllowedHeavy
// fails when an entry is no longer in the closure (shrink the list), so the list
// can only describe what is really there. A library that is not forbidden and not
// listed here is not covered by this guard; adding one to internal/core's closure
// is a review decision (see "What this does not check" below).
var stillAllowedHeavy = []string{
	"gorm.io/gorm",
}

// What this does not check: it looks at `go list -deps` of the production package
// with the default build tags (test files excluded, so the core TEST binary is not
// covered), and it cannot tell that an unlisted new library is heavy. Libraries are
// forbidden by name, one registered prefix per cut.

const coreImportPath = "github.com/keyorixhq/keyorix/internal/core"

const keyorixPrefix = "github.com/keyorixhq/keyorix/"

func matchesPrefix(dep, prefix string) bool {
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(dep, prefix)
	}
	return dep == prefix || strings.HasPrefix(dep, prefix+"/")
}

// listImportGraph returns ImportPath -> direct imports for the production closure
// of root.
func listImportGraph(t *testing.T, root string) map[string][]string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "-f", `{{.ImportPath}}|{{join .Imports " "}}`, root).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", root, err)
	}
	graph := map[string][]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		pkg, imports, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		graph[pkg] = strings.Fields(imports)
	}
	return graph
}

var (
	coreGraphOnce sync.Once
	coreGraph     map[string][]string
)

func coreClosure(t *testing.T) map[string][]string {
	t.Helper()
	coreGraphOnce.Do(func() { coreGraph = listImportGraph(t, coreImportPath) })
	if coreGraph == nil {
		t.Skip("import graph unavailable")
	}
	return coreGraph
}

// chainTo returns the shortest import chain root -> ... -> target in graph, or nil.
func chainTo(graph map[string][]string, root, target string) []string {
	prev := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == target {
			var chain []string
			for p := cur; p != ""; p = prev[p] {
				chain = append(chain, p)
			}
			slices.Reverse(chain)
			return chain
		}
		for _, next := range graph[cur] {
			if _, seen := prev[next]; seen {
				continue
			}
			if _, inGraph := graph[next]; !inGraph {
				continue
			}
			prev[next] = cur
			queue = append(queue, next)
		}
	}
	return nil
}

// forbiddenViolations returns one message per forbidden package found in graph's
// closure of root, naming the keyorix package that imports it and the chain from
// root. Sorted, so the output is deterministic.
func forbiddenViolations(graph map[string][]string, root string, forbidden map[string]string) []string {
	var msgs []string
	prefixes := make([]string, 0, len(forbidden))
	for p := range forbidden {
		prefixes = append(prefixes, p)
	}
	slices.Sort(prefixes)
	deps := make([]string, 0, len(graph))
	for dep := range graph {
		deps = append(deps, dep)
	}
	slices.Sort(deps)
	for _, dep := range deps {
		for _, prefix := range prefixes {
			if !matchesPrefix(dep, prefix) {
				continue
			}
			chain := chainTo(graph, root, dep)
			if chain == nil {
				continue // in the graph but not reachable from root
			}
			importer := "?"
			if len(chain) >= 2 {
				// The last keyorix package on the chain is the one that decided to import the library.
				for _, p := range slices.Backward(chain[:len(chain)-1]) {
					if strings.HasPrefix(p, keyorixPrefix) {
						importer = p
						break
					}
				}
			}
			msgs = append(msgs, fmt.Sprintf("%s is in the production closure of %s but is forbidden (%s). Imported by %s; chain: %s",
				dep, root, forbidden[prefix], importer, strings.Join(chain, " -> ")))
		}
	}
	return msgs
}

// TestCoreStaysLeanOfHeavyThirdParty fails when internal/core's production closure
// contains a package under any registered forbidden prefix, and says which keyorix
// package brought it back.
func TestCoreStaysLeanOfHeavyThirdParty(t *testing.T) {
	for _, msg := range forbiddenViolations(coreClosure(t), coreImportPath, forbiddenHeavyDeps) {
		t.Error(msg)
	}
}

// TestStillAllowedHeavy keeps stillAllowedHeavy exact: every entry must still be in
// the closure (otherwise shrink the list), and none may also be forbidden.
func TestStillAllowedHeavy(t *testing.T) {
	graph := coreClosure(t)
	for _, allowed := range stillAllowedHeavy {
		for prefix := range forbiddenHeavyDeps {
			if matchesPrefix(allowed, prefix) || matchesPrefix(prefix, allowed) {
				t.Errorf("%s is both on stillAllowedHeavy and forbidden (%s): pick one", allowed, prefix)
			}
		}
		found := false
		for dep := range graph {
			if matchesPrefix(dep, allowed) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("internal/core no longer imports %s: shrink stillAllowedHeavy to match", allowed)
		}
	}
}

// TestForbiddenViolations_SelfTest runs the checker on a synthetic graph: red on a
// planted violation (named importer and chain), green on the corrected graph and on
// an unrelated prefix.
func TestForbiddenViolations_SelfTest(t *testing.T) {
	const (
		root  = keyorixPrefix + "internal/core"
		files = keyorixPrefix + "internal/securefiles"
		env   = keyorixPrefix + "internal/secretenv"
	)
	forbidden := map[string]string{"example.com/cobra/": "test cut"}
	bad := map[string][]string{
		root:                     {env, files},
		env:                      nil,
		files:                    {"example.com/cobra/cmd"},
		"example.com/cobra/cmd":  {"example.com/cobra/flag"},
		"example.com/cobra/flag": nil,
	}
	msgs := forbiddenViolations(bad, root, forbidden)
	if len(msgs) != 2 {
		t.Fatalf("want 2 violations (cmd and flag), got %d: %v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "Imported by "+files+";") ||
		!strings.Contains(msgs[0], "chain: "+root+" -> "+files+" -> example.com/cobra/cmd") {
		t.Errorf("violation does not name the importing keyorix package and the chain: %s", msgs[0])
	}
	// A library reached only through another library is still pinned on the keyorix package above it.
	if !strings.Contains(msgs[1], "Imported by "+files+";") {
		t.Errorf("transitive violation must name the last keyorix package on the chain: %s", msgs[1])
	}

	good := map[string][]string{root: {env}, env: nil, files: {"example.com/cobra/cmd"}, "example.com/cobra/cmd": nil}
	if msgs := forbiddenViolations(good, root, forbidden); len(msgs) != 0 {
		t.Errorf("package outside the closure must not be reported: %v", msgs)
	}
	if msgs := forbiddenViolations(bad, root, map[string]string{"example.com/other": "x"}); len(msgs) != 0 {
		t.Errorf("unrelated prefix must not match: %v", msgs)
	}
	// Prefix semantics: no trailing slash matches the package and below, not a sibling with the same stem.
	if matchesPrefix("gopkg.in/yaml.v3x", "gopkg.in/yaml.v3") || !matchesPrefix("gopkg.in/yaml.v3", "gopkg.in/yaml.v3") {
		t.Error("matchesPrefix without trailing slash must be exact-or-subpackage")
	}
}
