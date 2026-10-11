// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("post_projects_withtransaction", opScopedBestEffortTable{
		op: "REST POST /api/v1/projects", method: "WithTransaction", tables: []string{"Environment", "AuditEvent"},
		minNthCall:          2,
		requireLogSubstring: "created without its environment",
	})
}
