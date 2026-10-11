// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2657", g4FuzzSeed{name: "2657", program: []byte{14, 0, 13, 0}}) // #2657: TransitionMembership activate vs revoke (fixed, #2669)
}
