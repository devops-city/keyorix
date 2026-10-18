// schema_epoch_tripwire_test.go — #1674 / ADR-101.
//
// currentSchemaEpoch's monotonic-refusal mechanism (ADR-097) is a known,
// deliberately-not-yet-fixed gap for multi-replica rolling upgrades: it cannot
// distinguish "a sibling replica already migrated, this pod is mid-rollout" from
// "an operator genuinely downgraded" (see docs/adr-101-schema-epoch-compatibility-
// floor.md for the full reasoning and the rejected alternatives). ADR-101's
// compatibility floor (minCompatibleSchemaEpoch, recorded as
// schema_min_compatible_epoch) is the mechanism that closes it, and it is in place.
//
// This test is the enforcement mechanism ADR-101 itself requires: it fails on any
// change to currentSchemaEpoch that is not accompanied by an update of the expected
// value here, with a message pointing straight at the design decision. It is not a
// statement that raising the epoch is wrong -- it's a checkpoint ensuring whoever
// does it meets ADR-101 (decide minCompatibleSchemaEpoch) at the moment it matters.
//
// History: 1 -> 2 for secret_nodes.purge_at (#3021), an additive nullable column an
// older binary neither reads nor maintains. That is NOT safe (an epoch-1 restore/delete
// leaves a stale purge_at), so minCompatibleSchemaEpoch is raised to 2.
// 2 -> 3 for pending_audit_events (SUSPEND-AUDIT-LOUD), an additive table an epoch-2
// binary never reads or writes; rows it leaves are drained by the next epoch-3
// replica's backfill, so the floor stays 2.
// 3 -> 4 for machine_identities.cascade_suspended_project_id/_at (#3433). An epoch-3
// binary neither sets nor clears the marker; its writes still move updated_at, which the
// epoch-4 restore requires unchanged, so it can only make the restore re-activate LESS
// (fail closed). The floor stays 2 (see minCompatibleSchemaEpoch's doc).
package storage

import "testing"

func TestCurrentSchemaEpoch_Is4_SeeADR101(t *testing.T) {
	if currentSchemaEpoch != 4 {
		t.Fatalf(
			"currentSchemaEpoch is now %d (expected 4) -- STOP: docs/adr-101-schema-epoch-compatibility-floor.md "+
				"requires every bump to also decide minCompatibleSchemaEpoch (additive-and-safe leaves it "+
				"unchanged; a migration an older binary cannot safely run against raises it to the new epoch). "+
				"Make that decision in factory.go, THEN update this test's expected value alongside your "+
				"epoch bump -- do not just raise the constant here.",
			currentSchemaEpoch)
	}
	if minCompatibleSchemaEpoch != 2 {
		t.Fatalf("minCompatibleSchemaEpoch is %d; the purge_at column (epoch 2) is NOT safe for an epoch-1 binary: its "+
			"RestoreSecret/RestoreProject do not clear purge_at and its DeleteSecret does not re-stamp it, so a restore+re-delete "+
			"on an old replica leaves a stale date and the new purge job hard-deletes before the date shown (irreversible). "+
			"The floor must be 2 so epoch-1 binaries refuse to start (INV-STORE-secret-purge-never-before-shown-date)", minCompatibleSchemaEpoch)
	}
}
