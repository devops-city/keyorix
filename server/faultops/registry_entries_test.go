// registry_entries_test.go — how this package's append-only exemption tables
// are populated. READ THIS before adding a row to any of them.
//
// One file per entry; never append to a shared list.
//
// The exemption tables below used to be single composite literals that every
// fuzzer/security PR appended to, so any two PRs that each added one row
// conflicted (merge-tick logged 21 such conflict events in two days on
// fuzz_storage_fault_operations_test.go and oracle_a_by_design_test.go alone;
// CHURN-2). Each row now lives in its OWN file that registers itself from
// init(), so two PRs adding two rows touch two different files and never
// conflict:
//
//	knownOpenTolerances               known_open_tolerances_entry_<slug>_test.go
//	opScopedBestEffortTables          op_scoped_best_effort_entry_<slug>_test.go
//	effectThenErrorExtraExclusions    effect_then_error_exclusion_entry_<slug>_test.go
//	bestEffortTables                  best_effort_tables_entry_<method>_test.go
//	nonLoadBearingAuthzReadExceptions non_load_bearing_authz_read_entry_<slug>_test.go
//	oracleAByDesignErrors             oracle_a_by_design_entry_<slug>_test.go
//
// To add a row: create ONE new file named as above whose init() calls the
// table's register function with a unique <slug> (the registered name), and put
// the row's reasoning comment above the call, in that file. Do NOT add the row
// to the table's declaration in fuzz_storage_fault_operations_test.go /
// oracle_a_by_design_test.go (the declarations are empty on purpose).
//
// Properties the helpers below guarantee:
//   - Deterministic order. The table is kept sorted by the registered name no
//     matter in what order the compiler runs the files' init()s, so a
//     first-match-wins consumer behaves the same on every machine.
//   - No silent shadowing. Registering the same name twice panics at package
//     init, which fails every test in the package loudly.
//
// Every guard over these tables (TestKnownOpenTolerances_*, TestOracleAByDesign_*,
// TestOpScopedAcceptableByDesign_*, ...) reads the populated variables exactly
// as before; only where the rows are written changed.
package faultops

import (
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

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
type mapRegistry[V any] struct {
	table map[string]V
	label string
}

func (r mapRegistry[V]) add(key string, v V) {
	if _, dup := r.table[key]; dup {
		panic(fmt.Sprintf("%s: key %q is registered twice — one file per entry, with a unique key", r.label, key))
	}
	r.table[key] = v
}

var (
	knownOpenTolerancesReg = &sliceRegistry[knownOpenTolerance]{table: &knownOpenTolerances, label: "knownOpenTolerances"}
	opScopedBestEffortReg  = &sliceRegistry[opScopedBestEffortTable]{table: &opScopedBestEffortTables, label: "opScopedBestEffortTables"}
	effectThenErrorExclReg = &sliceRegistry[effectThenErrorExclusion]{table: &effectThenErrorExtraExclusions, label: "effectThenErrorExtraExclusions"}
	nonLoadBearingReg      = &sliceRegistry[nonLoadBearingException]{table: &nonLoadBearingAuthzReadExceptions, label: "nonLoadBearingAuthzReadExceptions"}
	oracleAByDesignReg     = &sliceRegistry[oracleAByDesignError]{table: &oracleAByDesignErrors, label: "oracleAByDesignErrors"}
	bestEffortTablesReg    = mapRegistry[[]string]{table: bestEffortTables, label: "bestEffortTables"}
)

func registerKnownOpenTolerance(name string, e knownOpenTolerance) {
	knownOpenTolerancesReg.add(name, e)
}
func registerOpScopedBestEffort(name string, e opScopedBestEffortTable) {
	opScopedBestEffortReg.add(name, e)
}
func registerEffectThenErrorExclusion(name string, e effectThenErrorExclusion) {
	effectThenErrorExclReg.add(name, e)
}
func registerNonLoadBearingAuthzRead(name string, e nonLoadBearingException) {
	nonLoadBearingReg.add(name, e)
}
func registerOracleAByDesign(name string, e oracleAByDesignError) { oracleAByDesignReg.add(name, e) }
func registerBestEffortTable(method string, tables []string)      { bestEffortTablesReg.add(method, tables) }

// opScopedBestEffortTable is one row of opScopedBestEffortTables (declared in
// fuzz_storage_fault_operations_test.go, where the rationale for the table lives).
type opScopedBestEffortTable struct {
	op, method string
	tables     []string
	// minNthCall restricts this exemption to fault injections at or after this
	// 1-indexed call number; 0 means unrestricted (every pre-existing entry's
	// behavior, unchanged).
	minNthCall int
	// requireLogSubstring, when non-empty, additionally requires this exact
	// substring to appear in the op's captured log output (execLog) for this
	// exemption to apply. Empty (the zero value, every pre-existing entry)
	// means no log-evidence check — unchanged behavior for those entries.
	requireLogSubstring string
	// pinnedKinds, when non-empty, are the fault kinds this entry was reviewed
	// for, at call ordinal max(1, minNthCall).
	// TestOpScopedBestEffort_PinnedEntriesAreLoadBearing drives each one through
	// the real oracle and fails if the entry is dead. Empty for the entries that
	// predate it (ORPHAN-2): they are not covered by that staleness check.
	pinnedKinds []faultstorage.FaultKind
}

// effectThenErrorExclusion is one row of effectThenErrorExtraExclusions
// (declared in fuzz_storage_fault_operations_test.go).
type effectThenErrorExclusion struct {
	op, method string
	tables     []string
	// columns narrows one table to a column-level exclusion instead of
	// removing it from the comparison entirely (see hashExcludingColumns):
	// key is the table name, value is the column(s) stripped from every row
	// of that table before it's hashed. A table named here does NOT also need
	// to be named in `tables` -- the two are independent, applied together.
	columns map[string][]string
}

// The three tables below are empty today; they are registries too so the next
// row is a new file (tolerance_dead_pending_triage_entry_<slug>_test.go,
// tolerance_staleness_undrivable_entry_<slug>_test.go,
// multi_step_ambiguous_commit_entry_<slug>_test.go), not an edit to a literal
// that the next PR would also edit.
var (
	toleranceDeadPendingTriageReg   = mapRegistry[string]{table: toleranceDeadPendingTriage, label: "toleranceDeadPendingTriage"}                                      //nolint:unused // first row of this empty table is a new file, see REGISTRY-ENTRIES.md
	toleranceStalenessUndrivableReg = mapRegistry[bool]{table: toleranceStalenessUndrivable, label: "toleranceStalenessUndrivable"}                                    //nolint:unused // first row of this empty table is a new file, see REGISTRY-ENTRIES.md
	multiStepAmbiguousCommitReg     = &sliceRegistry[nonLoadBearingException]{table: &multiStepAmbiguousCommitExceptions, label: "multiStepAmbiguousCommitExceptions"} //nolint:unused // first row of this empty table is a new file, see REGISTRY-ENTRIES.md
)

func registerToleranceDeadPendingTriage(label, note string) { //nolint:unused // see REGISTRY-ENTRIES.md
	toleranceDeadPendingTriageReg.add(label, note)
}
func registerToleranceStalenessUndrivable(label string) { //nolint:unused // see REGISTRY-ENTRIES.md
	toleranceStalenessUndrivableReg.add(label, true)
}
func registerMultiStepAmbiguousCommit(name string, e nonLoadBearingException) { //nolint:unused // see REGISTRY-ENTRIES.md
	multiStepAmbiguousCommitReg.add(name, e)
}
