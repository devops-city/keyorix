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
package storage

import "testing"

func TestCurrentSchemaEpoch_Is3_SeeADR101(t *testing.T) {
	if currentSchemaEpoch != 3 {
		t.Fatalf(
			"currentSchemaEpoch is now %d (expected 3) -- STOP: docs/adr-101-schema-epoch-compatibility-floor.md "+
				"requires every bump to also decide minCompatibleSchemaEpoch (additive-and-safe leaves it "+
				"unchanged; a migration an older binary cannot safely run against raises it to the new epoch). "+
				"Make that decision in factory.go, THEN update this test's expected value alongside your "+
				"epoch bump -- do not just raise the constant here.",
			currentSchemaEpoch)
	}
	if minCompatibleSchemaEpoch != 3 {
		t.Fatalf("minCompatibleSchemaEpoch is %d; the floor must be 3. Epoch-1 binaries mishandle purge_at "+
			"(INV-STORE-secret-purge-never-before-shown-date), and epoch-2 binaries rewrite the v2 audit retention anchor as v1, "+
			"dropping the purged count (#3359), and never write secret_nodes.suspend_clear_synced_copies (#3362)", minCompatibleSchemaEpoch)
	}
}
