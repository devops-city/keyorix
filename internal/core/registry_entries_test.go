// registry_entries_test.go — how this package's append-only guard tables are
// populated. READ THIS before adding a row to any of them.
//
// One file per entry; never append to a shared list.
//
// These tables used to be single composite literals (or runs of f.Add lines)
// that every security PR appended to, so any two PRs that each added one row
// conflicted (merge-tick logged 19 such conflict events in two days on
// cross_replica_invariants_fuzz_test.go and 13 on mfa_stepup_purpose_guard_test.go
// alone; CHURN-2). Each row now lives in its OWN file that registers itself
// from init(), so two PRs adding two rows touch two different files:
//
//	(mfaStepUpPurposeAllowlist moved to internal/core/guards, see its registry_entries_test.go)
//	g4FuzzSeedPrograms          cross_replica_seed_entry_<issue>_test.go
//	pendingSeedFix              pending_seed_fix_entry_<issue>_test.go
//
// To add a row: create ONE new file named as above whose init() calls the
// table's register function, with the row's reasoning comment above the call.
// Do NOT add the row to the table's declaration (those are empty on purpose).
//
// Properties the helpers below guarantee:
//   - Deterministic order. Slice tables are kept sorted by the registered name
//     whatever order the compiler runs the files' init()s in.
//   - No silent shadowing. Registering a name/key twice panics at package init,
//     which fails every test in the package loudly.
//
// Every guard over these tables reads the populated variables exactly as before.
package core

import (
	"fmt"
	"sort"
)

// g4FuzzSeed is one FuzzCrossReplicaInvariants seed: a program (4 bytes per
// racing pair: kindA, miscA, kindB, miscB) for an issue already fixed on main.
type g4FuzzSeed struct {
	name    string // registered name, sorted on; the issue number
	program []byte
}

// g4FuzzSeedPrograms holds the seeds FuzzCrossReplicaInvariants f.Adds (plus
// the empty program it adds itself). Only issues already fixed on main belong
// here — a seed for a still-open issue would fail this test on main today.
// One file per seed: see the header of this file.
var g4FuzzSeedPrograms = []g4FuzzSeed{}

// sliceRegistry keeps *table sorted by entry name, whatever order init()s run in.
type sliceRegistry[T any] struct {
	table *[]T
	label string
	names []string
}

func (r *sliceRegistry[T]) add(name string, v T) {
	i := sort.SearchStrings(r.names, name)
	if i < len(r.names) && r.names[i] == name {
		panic(fmt.Sprintf("%s: entry %q is registered twice — one file per entry, with a unique name", r.label, name))
	}
	var zero T
	r.names = append(r.names, "")
	copy(r.names[i+1:], r.names[i:])
	r.names[i] = name
	*r.table = append(*r.table, zero)
	copy((*r.table)[i+1:], (*r.table)[i:])
	(*r.table)[i] = v
}

// mapRegistry adds entries to a map keyed by the entry's real key, panicking
// on a duplicate key instead of silently overwriting it.
type mapRegistry[V any] struct { //nolint:unused // only pendingSeedFixRegistry uses it today (its table is empty); see REGISTRY-ENTRIES.md
	table map[string]V
	label string
}

func (r mapRegistry[V]) add(key string, v V) { //nolint:unused // see the type
	if _, dup := r.table[key]; dup {
		panic(fmt.Sprintf("%s: key %q is registered twice — one file per entry, with a unique key", r.label, key))
	}
	r.table[key] = v
}

var (
	g4FuzzSeedsReg         = &sliceRegistry[g4FuzzSeed]{table: &g4FuzzSeedPrograms, label: "g4FuzzSeedPrograms"}
	pendingSeedFixRegistry = mapRegistry[int]{table: pendingSeedFix, label: "pendingSeedFix"} //nolint:unused // the table is empty today; its first row is a new file, see REGISTRY-ENTRIES.md
)

func registerG4FuzzSeed(name string, s g4FuzzSeed) {
	g4FuzzSeedsReg.add(name, s)
}
func registerPendingSeedFix(issue string, pr int) { pendingSeedFixRegistry.add(issue, pr) } //nolint:unused // see REGISTRY-ENTRIES.md
