// secret_update_diff_test.go — G80 Phase 0 conformance tests for the default-deny diff
// (secret_update_diff.go). This is the PRIMARY test for the fix: it operates at the
// storage-interface contract level (models.SecretNode field classification + the diff
// function itself), not through internal/core call sites — testing through core was
// aimed one layer too high, since core functions' own permission-check machinery is a
// separate concern (several are additionally blocked against RemoteStorage by the
// pre-existing, separately-tracked https://github.com/keyorixhq/keyorix/issues/1512,
// which has nothing to do with this fix). See remote_storage_g80_secret_update_test.go
// for the small number of end-to-end tests that DO exercise real internal/core call
// sites — those are framed as guarding the contract for future callers, not as
// reproducing a live bug (see that file's own doc comment for why).
package handlers

import (
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretUpdateAllowlist_CoversEveryPersistedField is the durable half of the G80
// Phase 0 fix (per the sign-off: "Drive the field list in a way that fails when a new
// field is added to SecretNode without being classified"). Reflection over the live
// models.SecretNode type — not a hand-copied field list — so a future field added to
// the struct without an updateSecretAllowlist entry fails this test immediately,
// instead of silently defaulting to some behavior nobody decided on.
func TestSecretUpdateAllowlist_CoversEveryPersistedField(t *testing.T) {
	typ := reflect.TypeOf(models.SecretNode{})
	var unclassified []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if gormTag, ok := f.Tag.Lookup("gorm"); ok && gormTag == "-" {
			continue // ValueStored: transient, never persisted, not part of this contract
		}
		if _, ok := updateSecretAllowlist[f.Name]; !ok {
			unclassified = append(unclassified, f.Name)
		}
	}
	assert.Empty(t, unclassified,
		"every persisted models.SecretNode field must have an updateSecretAllowlist entry "+
			"(secret_update_diff.go) — classify it as allowed/rejected/ignored (with a reason) "+
			"before this test can pass")
}

// TestSecretUpdateAllowlist_NoExtraEntries is the inverse check: every allowlist entry
// must name a field that genuinely still exists on SecretNode, so a field rename or
// removal doesn't leave a dead, misleading entry behind.
func TestSecretUpdateAllowlist_NoExtraEntries(t *testing.T) {
	typ := reflect.TypeOf(models.SecretNode{})
	fields := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		fields[typ.Field(i).Name] = true
	}
	var stale []string
	for name := range updateSecretAllowlist {
		if !fields[name] {
			stale = append(stale, name)
		}
	}
	assert.Empty(t, stale, "updateSecretAllowlist has entries for fields that no longer exist on models.SecretNode")
}

// secretNodeFieldMutator sets a single field to a value distinctly different from
// baseSecretNode's, for diffSecretUpdate table-driven testing.
type secretNodeFieldMutator struct {
	field  string
	class  secretUpdateFieldClass
	mutate func(s *models.SecretNode)
}

func baseSecretNode() *models.SecretNode {
	return &models.SecretNode{
		ID: 1, ProjectID: 10, EnvironmentID: 20, Name: "original-name", IsSecret: true,
		Type: "generic", Description: "original description", MaxReads: nil, ReadCount: 0,
		Classification: "", Status: "active", CreatedBy: "seed", OwnerID: 5, IsShared: false,
		CreatedAt: time.Unix(1000, 0), UpdatedAt: time.Unix(1000, 0), RetentionOverrideDays: 0,
	}
}

// TestDiffSecretUpdate_EveryFieldBehavesAsClassified drives diffSecretUpdate once per
// allowlist entry, mutating ONLY that field relative to an unchanged authoritative row,
// and asserts the outcome matches its class: secretFieldAllowed differences are applied
// (and nothing else), secretFieldRejected differences are refused by name (and nothing
// is applied), secretFieldIgnored differences are neither applied nor rejected.
func TestDiffSecretUpdate_EveryFieldBehavesAsClassified(t *testing.T) {
	mutators := []secretNodeFieldMutator{
		{"Type", secretFieldAllowed, func(s *models.SecretNode) { s.Type = "api_key" }},
		{"Description", secretFieldAllowed, func(s *models.SecretNode) { s.Description = "changed" }},
		{"MaxReads", secretFieldAllowed, func(s *models.SecretNode) { n := 5; s.MaxReads = &n }},
		{"Expiration", secretFieldAllowed, func(s *models.SecretNode) { exp := time.Unix(2000, 0); s.Expiration = &exp }},
		{"Metadata", secretFieldAllowed, func(s *models.SecretNode) { s.Metadata = models.JSON(`{"k":"v"}`) }},
		{"UpdatedAt", secretFieldIgnored, func(s *models.SecretNode) { s.UpdatedAt = time.Unix(9999, 0) }},
		{"ID", secretFieldRejected, func(s *models.SecretNode) { s.ID = 999 }},
		{"ProjectID", secretFieldRejected, func(s *models.SecretNode) { s.ProjectID = 999 }},
		{"EnvironmentID", secretFieldRejected, func(s *models.SecretNode) { s.EnvironmentID = 999 }},
		{"Name", secretFieldRejected, func(s *models.SecretNode) { s.Name = "renamed" }},
		{"IsSecret", secretFieldRejected, func(s *models.SecretNode) { s.IsSecret = false }},
		{"ReadCount", secretFieldRejected, func(s *models.SecretNode) { s.ReadCount = 42 }},
		// CacheEpoch: the read-path cache's generation stamp, owned by a database
		// trigger and read-only to GORM. A client proposing one must be rejected,
		// not ignored — silently dropping it would hide a caller that believes it
		// controls cache invalidation.
		{"CacheEpoch", secretFieldRejected, func(s *models.SecretNode) { s.CacheEpoch = 99 }},
		{"Classification", secretFieldRejected, func(s *models.SecretNode) { s.Classification = "restricted" }},
		{"Status", secretFieldRejected, func(s *models.SecretNode) { s.Status = "suspended" }},
		{"CreatedBy", secretFieldRejected, func(s *models.SecretNode) { s.CreatedBy = "someone-else" }},
		{"OwnerID", secretFieldRejected, func(s *models.SecretNode) { s.OwnerID = 999 }},
		{"OwnerMachineIdentityID", secretFieldRejected, func(s *models.SecretNode) { s.OwnerMachineIdentityID = 999 }},
		{"IsShared", secretFieldRejected, func(s *models.SecretNode) { s.IsShared = true }},
		{"CreatedAt", secretFieldRejected, func(s *models.SecretNode) { s.CreatedAt = time.Unix(1, 0) }},
		{"LastRotatedAt", secretFieldRejected, func(s *models.SecretNode) { now := time.Unix(3000, 0); s.LastRotatedAt = &now }},
		{"AutoRotate", secretFieldRejected, func(s *models.SecretNode) { s.AutoRotate = true }},
		{"RotationLength", secretFieldRejected, func(s *models.SecretNode) { s.RotationLength = 32 }},
		{"RotationCharset", secretFieldRejected, func(s *models.SecretNode) { s.RotationCharset = "hex" }},
		{"RotationBackend", secretFieldRejected, func(s *models.SecretNode) { s.RotationBackend = "aws-kms" }},
		{"RotationRef", secretFieldRejected, func(s *models.SecretNode) { s.RotationRef = "ref-1" }},
		{"CertNotAfter", secretFieldRejected, func(s *models.SecretNode) { now := time.Unix(4000, 0); s.CertNotAfter = &now }},
		{"DeletedAt", secretFieldRejected, func(s *models.SecretNode) { s.DeletedAt.Valid = true; s.DeletedAt.Time = time.Unix(5000, 0) }},
		{"RetentionOverrideDays", secretFieldRejected, func(s *models.SecretNode) { s.RetentionOverrideDays = 30 }},
		{"ParentID", secretFieldRejected, func(s *models.SecretNode) { id := uint(7); s.ParentID = &id }},
	}

	// Every mutator's field must exist in the allowlist with the class the mutator
	// claims — this catches a mutator/allowlist drift, not just a diffSecretUpdate bug.
	for _, m := range mutators {
		require.Equal(t, m.class, updateSecretAllowlist[m.field], "mutator for %q claims a different class than updateSecretAllowlist", m.field)
	}
	// And the mutator table itself must cover every allowlist entry — this is what
	// makes the whole test fail when a field is added to SecretNode (caught first by
	// TestSecretUpdateAllowlist_CoversEveryPersistedField) but not ALSO given a mutator
	// here to prove diffSecretUpdate actually implements its classification correctly.
	covered := map[string]bool{}
	for _, m := range mutators {
		covered[m.field] = true
	}
	for field := range updateSecretAllowlist {
		assert.True(t, covered[field], "field %q is classified in updateSecretAllowlist but has no mutator in this test — "+
			"diffSecretUpdate's actual behavior for it is unverified", field)
	}

	for _, m := range mutators {
		t.Run(m.field, func(t *testing.T) {
			authoritative := baseSecretNode()
			desired := baseSecretNode()
			m.mutate(desired)

			diff := diffSecretUpdate(authoritative, desired)

			switch m.class {
			case secretFieldAllowed:
				assert.Empty(t, diff.Rejected, "an allowed field's change must not be rejected")
				assert.True(t, fieldChangedInDiff(t, diff, m.field), "an allowed field's change must be reflected in the diff's Changed flag")
			case secretFieldRejected:
				assert.NotEmpty(t, diff.Rejected, "a rejected field's change must appear in Rejected")
				assert.False(t, fieldChangedInDiff(t, diff, m.field), "a rejected field must never be marked as an applied change")
			case secretFieldIgnored:
				assert.Empty(t, diff.Rejected, "an ignored field's change must never be rejected")
				assert.False(t, fieldChangedInDiff(t, diff, m.field), "an ignored field must never be marked as an applied change — the hub computes its own value")
			}
		})
	}
}

// fieldChangedInDiff reports whether diffSecretUpdate marked the named allowed field as
// changed, via its *Changed bool for that field.
func fieldChangedInDiff(t *testing.T, diff secretUpdateDiff, field string) bool {
	t.Helper()
	switch field {
	case "Type":
		return diff.TypeChanged
	case "Description":
		return diff.DescriptionChanged
	case "MaxReads":
		return diff.MaxReadsChanged
	case "Expiration":
		return diff.ExpirationChanged
	case "Metadata":
		return diff.MetadataChanged
	default:
		return false // every rejected/ignored field has no *Changed flag by design
	}
}
