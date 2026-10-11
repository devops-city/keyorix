// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2651", g4FuzzSeed{name: "2651", program: []byte{2, 0, 39, 0}}) // #2651: DeleteProject vs CreateDynamicSecretConfig (fixed, #2675)
}
