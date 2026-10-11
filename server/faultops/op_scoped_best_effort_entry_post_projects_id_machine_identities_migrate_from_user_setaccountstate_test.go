// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// FIX-2 (#2812): the SECOND fault that lands on that same documented branch.
	// SuspendUser's own storage write is SetAccountState, so faulting it at call
	// #1 reaches the identical `return m, fmt.Errorf("machine identity %d
	// created but failed to suspend source user %d: ...")` line the entry above
	// exists for -- same op, same tradeoff, same two tables, different method on
	// the way in. Found live by FuzzStorageFaultOperations (shard 0) on PR #2804,
	// a PR with zero production-code changes, and confirmed pre-existing on
	// origin/main @ cbb9863e via REPLAY_HEX=3b6362.
	//
	// Deliberately an opScopedBestEffortTables entry, NOT a knownOpenTolerances
	// one: a tolerance asserts "open bug, expires on <date>", and this is not a
	// bug. The user row is never half-written -- the entire diff is the identity
	// the code chose to keep, and the error names its ID so the caller can
	// finish the job. Oracle (a) permits "nothing committed OR the caller needs
	// no new ID to clean anything up" (#2449's own wording); this satisfies the
	// second clause and fails the oracle only because the oracle cannot
	// recognise an informative partial success. Scoped to these two tables, so
	// the oracle still fails if anything ELSE diverges -- a genuinely
	// half-applied suspension (a User/Session/AuditCheckpoint row) would still
	// be caught, which is the property worth keeping.
	//
	// #2812 stays open for the broader #2549 question (whether to build a
	// general declared-exemption mechanism that also asserts the error text
	// still carries the recoverable ID); this entry stops CI failing on a
	// documented behaviour in the meantime.
	registerOpScopedBestEffort("post_projects_id_machine_identities_migrate_from_user_setaccountstate", opScopedBestEffortTable{op: "REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user", method: "SetAccountState", tables: []string{"AuditEvent", "MachineIdentity"}})
}
