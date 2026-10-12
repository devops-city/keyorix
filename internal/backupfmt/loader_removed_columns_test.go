package backupfmt

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// mismatchedModel finds a model whose position in RestoreOrder() differs
// from its position in the registry, and the registry-order name that sits
// at its restore position -- the name LoadArchive wrongly paired it with
// when it indexed modelTypeNames() by the restore-order loop index (#3086).
func mismatchedModel(t *testing.T) (name, table, wrongName string) {
	t.Helper()
	order, err := RestoreOrder()
	require.NoError(t, err)
	registry := modelTypeNames()
	byName := modelsByTypeName()
	for i, n := range order {
		if registry[i] == n {
			continue
		}
		s, err := parseSchema(byName[n])
		require.NoError(t, err)
		return n, s.Table, registry[i]
	}
	t.Fatal("restore order equals registry order; the parallel-index hazard cannot be exercised")
	return "", "", ""
}

func withKnownRemovedColumns(t *testing.T, entries ...removedColumn) {
	t.Helper()
	orig := knownRemovedColumns
	knownRemovedColumns = entries
	t.Cleanup(func() { knownRemovedColumns = orig })
}

func loadSingleTableArchive(t *testing.T, table string, columns []string) error {
	t.Helper()
	tar := "tables/" + table + ".ndjson"
	manifest := Manifest{
		FormatVersion: FormatVersion,
		Backend:       Backend,
		Tables:        []TableEntry{{Name: table, TarName: tar, RowCount: 0, Columns: columns}},
	}
	stagingDir := t.TempDir()
	require.NoError(t, stageEmptyTableFile(t, stagingDir, tar))
	dst := openTestDB(t)
	return dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	})
}

// TestLoadArchive_KnownRemovedColumnAppliesOnlyToItsOwnModel (#3086): a
// knownRemovedColumns entry for one model must allow the column on THAT
// model's table only. Before the fix LoadArchive named each model by
// modelTypeNames()[i] (registry order) while iterating restore order, so
// the allowance for the registry-order namesake was applied to a different
// table (fail-open on the §3.5 schema-delta check) and the real owner's
// allowance was refused.
func TestLoadArchive_KnownRemovedColumnAppliesOnlyToItsOwnModel(t *testing.T) {
	name, table, wrongName := mismatchedModel(t)
	const legacy = "legacy_removed_col"

	t.Run("allowance for another model is not applied to this table", func(t *testing.T) {
		withKnownRemovedColumns(t, removedColumn{Model: wrongName, Column: legacy})
		err := loadSingleTableArchive(t, table, []string{"id", legacy})
		require.Error(t, err, "allowance for %s must not apply to %s's table %q", wrongName, name, table)
		require.Contains(t, err.Error(), legacy)
		require.Contains(t, err.Error(), "model "+name, "error must name the model whose table was checked")
		require.NotContains(t, err.Error(), "model "+wrongName)
	})

	t.Run("allowance for this model applies to its own table", func(t *testing.T) {
		withKnownRemovedColumns(t, removedColumn{Model: name, Column: legacy})
		require.NoError(t, loadSingleTableArchive(t, table, []string{"id", legacy}))
	})
}
