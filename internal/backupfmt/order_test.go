package backupfmt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRestoreOrder_EveryReferenceFieldIsClassified is design-b3-backup-v2.md
// §3.4's own required guard (Andrei, 2026-09-28): every ID-shaped field on
// every live model must be classified as a naming-convention match, an
// explicit override, a self-reference, or a not-a-reference -- never
// silently skipped. A new model or field can then never silently fall out
// of restore ordering.
func TestRestoreOrder_EveryReferenceFieldIsClassified(t *testing.T) {
	_, unresolved := classifyAll()
	require.Empty(t, unresolved,
		"these ID-shaped fields are neither a naming-convention match nor listed in referenceOverrides/"+
			"notReferences/selfReferences -- classify each one explicitly")
}

// TestRestoreOrder_NoStaleOverrideOrExclusionEntries fails if
// referenceOverrides/notReferences/selfReferences names a (model, field)
// pair that no longer exists -- a renamed or removed field left behind in
// one of these tables would silently stop being applied (classifyAll simply
// wouldn't find that key), masking exactly the drift these tables exist to
// prevent being silent about.
func TestRestoreOrder_NoStaleOverrideOrExclusionEntries(t *testing.T) {
	live := make(map[[2]string]bool)
	all := modelTypeNames()
	models := modelsByTypeName()
	for _, name := range all {
		for _, f := range idShapedFields(models[name]) {
			live[[2]string{name, f}] = true
		}
	}

	for _, o := range referenceOverrides {
		require.True(t, live[[2]string{o.Model, o.Field}],
			"referenceOverrides has a stale entry: %s.%s no longer exists as an ID-shaped field", o.Model, o.Field)
	}
	for _, n := range notReferences {
		require.True(t, live[[2]string{n.Model, n.Field}],
			"notReferences has a stale entry: %s.%s no longer exists as an ID-shaped field", n.Model, n.Field)
	}
	for _, s := range selfReferences {
		require.True(t, live[[2]string{s.Model, s.Field}],
			"selfReferences has a stale entry: %s.%s no longer exists as an ID-shaped field", s.Model, s.Field)
	}
}

// TestRestoreOrder_IsValidTopologicalSort asserts RestoreOrder()'s result
// actually respects every derived dependency edge: for every classified
// field with a cross-table reference, the referenced model appears strictly
// before the referencing model in the returned order.
func TestRestoreOrder_IsValidTopologicalSort(t *testing.T) {
	order, err := RestoreOrder()
	require.NoError(t, err)
	require.Equal(t, len(modelTypeNames()), len(order), "RestoreOrder must place every model exactly once")

	position := make(map[string]int, len(order))
	for i, n := range order {
		position[n] = i
	}

	classified, unresolved := classifyAll()
	require.Empty(t, unresolved)
	for _, c := range classified {
		if c.Refs == "" || c.Refs == c.Model {
			continue
		}
		require.Less(t, position[c.Refs], position[c.Model],
			"%s (referenced by %s.%s) must come before %s in restore order", c.Refs, c.Model, c.Field, c.Model)
	}
}

// TestResolveByConvention_OnlyMatchesAFullModelNameSuffix pins the naming
// convention to "the field's remainder ends with the model's full name"
// (#3078). The reverse direction -- a model name that merely ends with the
// remainder -- resolved every SecretID field to MFASecret, because there is
// no "Secret" model for "SecretID" to name. Such a field must come back
// unresolved, so it can only be classified by an explicit referenceOverrides
// entry someone checked against the schema.
func TestResolveByConvention_OnlyMatchesAFullModelNameSuffix(t *testing.T) {
	names := modelTypeNames()

	for _, field := range []string{"SecretID", "ClientID", "ConfigID", "ProviderID", "VersionID"} {
		got, ok := resolveByConvention(field, names)
		require.False(t, ok, "%s must not resolve by convention (it would guess %q); list it in referenceOverrides", field, got)
	}

	got, ok := resolveByConvention("OwnerMachineIdentityID", names)
	require.True(t, ok)
	require.Equal(t, "MachineIdentity", got)
	got, ok = resolveByConvention("SecretNodeID", names)
	require.True(t, ok)
	require.Equal(t, "SecretNode", got)

	classified, unresolved := classifyAll()
	require.Empty(t, unresolved)
	overridden := make(map[[2]string]bool, len(referenceOverrides))
	for _, o := range referenceOverrides {
		overridden[[2]string{o.Model, o.Field}] = true
	}
	for _, c := range classified {
		if c.Refs == "" || overridden[[2]string{c.Model, c.Field}] {
			continue
		}
		require.True(t, strings.HasSuffix(strings.TrimSuffix(c.Field, "ID"), c.Refs),
			"%s.%s resolved by convention to %s, whose name the field does not end with", c.Model, c.Field, c.Refs)
	}
}

// TestRestoreOrder_SecretIDFieldsReferenceSecretNode: every field named
// SecretID holds a SecretNode.ID (#3078: all five were classified as
// references to MFASecret, so restore checked them against mfa_secrets).
func TestRestoreOrder_SecretIDFieldsReferenceSecretNode(t *testing.T) {
	classified, unresolved := classifyAll()
	require.Empty(t, unresolved)

	var seen []string
	for _, c := range classified {
		if c.Field != "SecretID" {
			continue
		}
		seen = append(seen, c.Model)
		require.Equal(t, "SecretNode", c.Refs, "%s.SecretID must reference SecretNode", c.Model)
	}
	require.Subset(t, seen,
		[]string{"AccessRequest", "AccessReviewItem", "SecretACL", "SecretVersionComment", "ShareRecord"},
		"a known SecretID field is no longer ID-shaped or no longer classified")
}
