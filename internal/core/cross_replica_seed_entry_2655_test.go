// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2655", g4FuzzSeed{name: "2655", program: []byte{27, 0, 26, 0}}) // #2655: ActivateMFA vs BeginMFAEnrollment (fixed, #2667)
}
