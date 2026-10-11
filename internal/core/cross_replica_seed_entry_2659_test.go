// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerG4FuzzSeed("2659", g4FuzzSeed{name: "2659", program: []byte{14, 0, 12, 0}}) // #2659: open-mode InviteMember vs revoke (fixed, #2852 — the race by #2669, the oracle here)
}
