// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2653", g4FuzzSeed{name: "2653", program: []byte{21, 0, 23, 0}}) // #2653: UpdateUser vs SuspendUser (fixed, #2785)
}
