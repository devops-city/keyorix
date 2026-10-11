// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2654", g4FuzzSeed{name: "2654", program: []byte{25, 0, 24, 0}}) // #2654: UpdateOwnProfile vs ChangePassword (fixed, #2785)
}
