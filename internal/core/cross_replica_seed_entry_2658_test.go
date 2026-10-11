// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2658", g4FuzzSeed{name: "2658", program: []byte{36, 0, 37, 0}}) // #2658 class: both admins' global role removed concurrently (fixed, #2665)
}
