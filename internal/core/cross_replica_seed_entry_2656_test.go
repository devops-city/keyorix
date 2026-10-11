// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2656", g4FuzzSeed{name: "2656", program: []byte{2, 0, 5, 0}}) // #2656: RestoreEnvironment vs DeleteProject (fixed, #2785)
}
