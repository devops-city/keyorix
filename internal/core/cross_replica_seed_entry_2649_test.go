// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2649", g4FuzzSeed{name: "2649", program: []byte{0, 0, 10, 0}}) // #2649: GrantSecretACL vs DeleteSecret (fixed, #2785)
}
