// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2646", g4FuzzSeed{name: "2646", program: []byte{0, 0, 6, 0}}) // #2646: ShareSecret vs DeleteSecret (fixed, #2785)
}
