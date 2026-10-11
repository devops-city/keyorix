// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2652", g4FuzzSeed{name: "2652", program: []byte{2, 0, 30, 0}}) // #2652: IssueLease vs DeleteProject (fixed, #2785)
}
