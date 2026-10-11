// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2660", g4FuzzSeed{name: "2660", program: []byte{28, 0, 29, 0}}) // #2660: AddSecretDependency both directions (fixed, #2670)
}
