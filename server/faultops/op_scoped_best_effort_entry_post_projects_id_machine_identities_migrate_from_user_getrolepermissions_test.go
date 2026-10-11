// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// MigrateUserToMachine (internal/core/migrate_user_to_machine.go) deliberately
	// returns the already-created machine identity ALONGSIDE a non-nil error when
	// GetRolePermissions fails after the identity row committed — the function's
	// own doc comment (lines 64-67) says so explicitly: "The identity exists;
	// report the partial state..." rather than attempt a compensating delete.
	// This is the default-branch (reported-error) analogue of bestEffortTables'
	// AddPasswordHistory entry: a documented, intentional "committed anyway, told
	// the caller" tradeoff, not a bug. Found live: FuzzStorageFaultOperations
	// (REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user,
	// fault=GetRolePermissions#1/error), Session CR round 2.
	registerOpScopedBestEffort("post_projects_id_machine_identities_migrate_from_user_getrolepermissions", opScopedBestEffortTable{op: "REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user", method: "GetRolePermissions", tables: []string{"AuditEvent", "MachineIdentity"}})
}
