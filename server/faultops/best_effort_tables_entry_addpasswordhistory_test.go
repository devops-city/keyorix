// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerBestEffortTable("AddPasswordHistory", []string{"PasswordHistory"})
}
