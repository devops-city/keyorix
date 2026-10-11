// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2647", g4FuzzSeed{name: "2647", program: []byte{0, 0, 7, 0}}) // #2647: ShareSecretWithGroup vs DeleteSecret (fixed, #2785)
}
