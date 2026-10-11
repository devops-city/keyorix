// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// CreateEnvironment: CreateProject/CreateProjectWithEnvs (internal/core/catalog.go)
	// seed a new project's default/requested environments in a loop after the
	// project row itself already committed, and treat a per-environment
	// failure as non-fatal — found live by a fuzz burst, which ALSO caught
	// that the "non-fatal; log and continue" comment on both loops discarded
	// the error with a bare `_ = err` instead of actually logging it (fixed
	// same PR: both now log.Printf a Warning naming the project and the
	// environment that failed to seed). The underlying "proceed without the
	// environment" behavior itself is unchanged and is the actual tradeoff
	// flagged here. FLAG FOR REVIEW (updated, item 4 of the UX-fixes batch):
	// "no caller-visible signal" above is no longer true for an operator or
	// automated sweep -- seedProjectEnvironment now writes an
	// EventProjectEnvironmentSeedFailed audit event (AuditEvent row, hence
	// that table joining the diff here too) for every failed/panicked seed,
	// once the outer transaction commits (reportProjectEnvironmentSeedFailures).
	// Still open: whether CreateProject should ALSO report which environments
	// seeded successfully in its own HTTP response, rather than only via the
	// audit trail. Left undecided, same as before.
	registerBestEffortTable("CreateEnvironment", []string{"Environment", "AuditEvent"})
}
