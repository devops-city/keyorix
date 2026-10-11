// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2648", g4FuzzSeed{name: "2648", program: []byte{9, 0, 8, 0}}) // #2648: RevokeShare vs UpdateSharePermission (fixed, #2666)
}
