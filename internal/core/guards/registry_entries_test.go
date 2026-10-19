// registry_entries_test.go — how this package's append-only guard table is
// populated. READ THIS before adding a row to it.
//
// One file per entry; never append to a shared list.
//
// mfaStepUpPurposeAllowlist used to live in internal/core (with the rest of the
// registry tables in internal/core/registry_entries_test.go) and moved here with
// the guard that reads it (CACHE-GUARDS-1): the guard scans the whole repository
// and needs nothing from core, so it runs in this package without compiling
// core's test archive. The mechanism is unchanged:
//
//	mfaStepUpPurposeAllowlist   mfa_stepup_purpose_allow_entry_<slug>_test.go
//
// To add a row: create ONE new file named as above, in THIS directory, whose
// init() calls registerMFAStepUpPurposeAllow, with the row's reasoning comment
// above the call. Do NOT add the row to the table's declaration (it is empty on
// purpose). Registering a key twice panics at package init, which fails every
// test in the package loudly.
package guards

import "fmt"

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

var mfaStepUpPurposeAllowReg = mapRegistry[mfaStepUpAllowEntry]{table: mfaStepUpPurposeAllowlist, label: "mfaStepUpPurposeAllowlist"}

func registerMFAStepUpPurposeAllow(key string, e mfaStepUpAllowEntry) {
	mfaStepUpPurposeAllowReg.add(key, e)
}
