package backupfmt

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// secretRefColumnNames are the DB column names that, anywhere in the schema,
// hold a secret_nodes.id or secret_versions.id. The enumeration is two
// independent sources so neither one's blind spot hides a column:
//
//  1. every classified reference edge whose parent table is secret_nodes or
//     secret_versions (referenceEdges, the same data restore's check walks);
//  2. every column with one of these names. #3078 showed (1) alone can
//     misclassify a SecretID column as a reference to mfa_secrets; this list
//     keeps such a column in scope whatever the edge says.
//
// What it does NOT see: a column that references a secret under a name not in
// this list AND is not classified as an edge to secret_nodes/secret_versions.
// referenceEdges' own TestRestoreOrder_EveryReferenceFieldIsClassified forces
// every ID-shaped field into an edge, so that case needs a misclassified edge.
var secretRefColumnNames = map[string]bool{
	"secret_id":            true,
	"secret_node_id":       true,
	"secret_version_id":    true,
	"version_id":           true,
	"dependent_secret_id":  true,
	"depends_on_secret_id": true,
}

// purgedDirectly are the references PurgeDeletedSecretsBefore deletes with its
// own statements (predating #3085). TestPurgeDeletedSecretsBefore_RemovesEveryClassifiedReference
// proves the rows really go.
var purgedDirectly = map[[2]string]bool{
	{"secret_versions", "secret_node_id"}:           true,
	{"secret_dependencies", "dependent_secret_id"}:  true,
	{"secret_dependencies", "depends_on_secret_id"}: true,
	{"secret_acls", "secret_id"}:                    true,
}

type tableColumn struct{ Table, Column string }

func discoverSecretRefColumns(t *testing.T) map[tableColumn]bool {
	t.Helper()
	found := map[tableColumn]bool{}

	edges, err := referenceEdges()
	require.NoError(t, err)
	for _, e := range edges {
		if e.ParentTable == "secret_nodes" || e.ParentTable == "secret_versions" {
			found[tableColumn{e.ChildTable, e.ChildColumn}] = true
		}
	}
	for _, m := range storage.AllModels() {
		s, err := parseSchema(m)
		require.NoError(t, err)
		for _, f := range s.Fields {
			if secretRefColumnNames[f.DBName] {
				found[tableColumn{s.Table, f.DBName}] = true
			}
		}
	}
	return found
}

// TestSecretReferencesAreClassified is the #3085 guard: every column that
// references a secret or a secret version is classified as exactly one of
//
//   - purged directly (purgedDirectly above),
//   - CASCADE (store.SecretPurgeCascades: the purge deletes the rows),
//   - HISTORICAL (HistoricalReferences: restore's check skips it, with a reason),
//
// and the children of every cascaded table are cascaded too. A new table with
// a secret reference fails here until someone decides which, so the purge
// cannot silently start orphaning rows that `admin restore` then refuses.
func TestSecretReferencesAreClassified(t *testing.T) {
	found := discoverSecretRefColumns(t)
	require.NotEmpty(t, found)

	cascade := map[tableColumn]bool{}
	cascadeTables := map[string]bool{}
	for _, c := range store.SecretPurgeCascades() {
		k := tableColumn{c.Table, c.Column}
		require.False(t, cascade[k], "%s.%s is listed twice in SecretPurgeCascades", c.Table, c.Column)
		cascade[k] = true
		cascadeTables[c.Table] = true
	}
	historical := map[tableColumn]bool{}
	for _, h := range HistoricalReferences() {
		require.NotEmpty(t, h.Why, "%s.%s is a historical reference with no stated reason", h.Table, h.Column)
		historical[tableColumn{h.Table, h.Column}] = true
	}
	direct := map[tableColumn]bool{}
	for k := range purgedDirectly {
		direct[tableColumn{k[0], k[1]}] = true
	}

	var unclassified, ambiguous, stale []string
	for k := range found {
		n := 0
		for _, set := range []map[tableColumn]bool{cascade, historical, direct} {
			if set[k] {
				n++
			}
		}
		switch n {
		case 0:
			unclassified = append(unclassified, k.Table+"."+k.Column)
		case 1:
		default:
			ambiguous = append(ambiguous, k.Table+"."+k.Column)
		}
	}
	for _, set := range []map[tableColumn]bool{cascade, historical, direct} {
		for k := range set {
			if !found[k] {
				stale = append(stale, k.Table+"."+k.Column)
			}
		}
	}
	sort.Strings(unclassified)
	sort.Strings(ambiguous)
	sort.Strings(stale)
	require.Empty(t, unclassified, "these columns reference a secret/version but are not classified: add each to "+
		"store.SecretPurgeCascades (purge deletes the rows) or historical_refs.go (immutable record, with a reason)")
	require.Empty(t, ambiguous, "these columns are classified more than once")
	require.Empty(t, stale, "these classification entries name a column that no longer references a secret")

	// Children of a cascaded table: their rows must go with it.
	indirect := map[tableColumn]bool{}
	for _, c := range store.SecretPurgeIndirectCascades() {
		indirect[tableColumn{c.Table, c.Column}] = true
	}
	edges, err := referenceEdges()
	require.NoError(t, err)
	var childOfCascaded []string
	seen := map[tableColumn]bool{}
	for _, e := range edges {
		k := tableColumn{e.ChildTable, e.ChildColumn}
		if !cascadeTables[e.ParentTable] || cascade[k] || direct[k] {
			continue
		}
		seen[k] = true
		if !indirect[k] {
			childOfCascaded = append(childOfCascaded, e.ChildTable+"."+e.ChildColumn+" -> "+e.ParentTable)
		}
	}
	sort.Strings(childOfCascaded)
	require.Empty(t, childOfCascaded, "these columns reference a table the secret purge deletes from, but are not in "+
		"store.SecretPurgeIndirectCascades: the purge would orphan them")
	for k := range indirect {
		require.True(t, seen[k], "SecretPurgeIndirectCascades entry %s.%s no longer references a cascaded table", k.Table, k.Column)
	}
}
