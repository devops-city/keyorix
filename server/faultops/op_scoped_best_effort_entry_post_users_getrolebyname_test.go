// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("post_users_getrolebyname", opScopedBestEffortTable{op: "REST POST /api/v1/users/", method: "GetRoleByName", tables: []string{"UserRole"}})
}
