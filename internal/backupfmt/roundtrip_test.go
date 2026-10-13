package backupfmt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestRoundTrip_WriteExtractVerifyLoad is the full backupfmt-level round
// trip design §11.1 asks for, scoped to a small model subset (the full
// 78-table registry round trip is H5's job): write a backup from a seeded
// source DB, extract it to a staging directory, verify the manifest
// signature against the staged bytes, wipe/re-migrate a fresh target DB,
// load the staged data into it inside a transaction, and assert the
// restored rows match the source exactly.
func TestRoundTrip_WriteExtractVerifyLoad(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Create(&models.Project{Name: "proj-1"}).Error)
	// PasswordHash is json:"-" -- deliberately DISTINCT per user (not the
	// same literal "x" for both) so a bug that drops this field is visible
	// as "value went missing/became empty", not masked by both rows
	// happening to share one value regardless.
	require.NoError(t, src.Create(&models.User{Username: "alice", Email: "a@example.com", PasswordHash: "alice-hash"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "bob", Email: "b@example.com", PasswordHash: "bob-hash"}).Error)

	testModels := []any{&models.Project{}, &models.Environment{}, &models.User{}}
	key := testManifestKey()

	var archive bytes.Buffer
	writtenManifest, err := writeBackupModels(src, testModels, 5, "", key,
		[]KeyFileEntry{{OriginalPath: "dek.key", TarName: "keyfiles/0", Mode: 0600, SHA256: "b5d54c39e66671c9731b9f471e585d8262cd4f54963f0c93082d8dcf334d4c78", Size: 4}},
		[][]byte{[]byte("fake")}, &archive)
	require.NoError(t, err)

	stagingDir := t.TempDir()
	extractedManifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)
	require.Equal(t, writtenManifest.Tables, extractedManifest.Tables)
	require.True(t, VerifyManifestSignature(extractedManifest, key))

	// Staged key file bytes must be byte-identical to what was written.
	stagedKey, err := readStagedFile(t, stagingDir, "keyfiles/0")
	require.NoError(t, err)
	require.Equal(t, []byte("fake"), stagedKey)

	dst := openTestDB(t) // fresh, already-migrated target (§3.4: "run normal migrations first")
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, extractedManifest, stagingDir)
	}))

	var users []models.User
	require.NoError(t, dst.Order("id ASC").Find(&users).Error)
	require.Len(t, users, 2)
	require.Equal(t, "alice", users[0].Username)
	require.Equal(t, "bob", users[1].Username)
	// PasswordHash is json:"-" -- must still survive the backup/restore row
	// encoding. Found live (H6): a version-skip upgrade proof restoring a
	// real, multi-role database into Postgres hit a UNIQUE constraint
	// violation on Role.NameFolded (also json:"-") because every restored
	// role's NameFolded came back "" -- json.Marshal(row) silently drops any
	// json:"-" field, and json:"-" exists to hide a field from HTTP API
	// responses, not to exempt it from being backed up.
	require.Equal(t, "alice-hash", users[0].PasswordHash, "json:\"-\" field PasswordHash must survive the backup/restore round trip")
	require.Equal(t, "bob-hash", users[1].PasswordHash, "json:\"-\" field PasswordHash must survive the backup/restore round trip")

	var projects []models.Project
	require.NoError(t, dst.Find(&projects).Error)
	require.Len(t, projects, 1)
	require.Equal(t, "proj-1", projects[0].Name)
}

// TestRoundTrip_MultipleRowsWithJSONDashUniqueColumn is the exact production
// shape that first surfaced this class of bug (H6's version-skip upgrade
// proof, restoring a real multi-role database into Postgres): several rows
// in the SAME table, each with a DIFFERENT value in a json:"-"-tagged,
// uniquely-indexed column (Role.NameFolded). Before the row_codec.go fix,
// json.Marshal(row) dropped NameFolded from every archived row, so every
// restored row loaded with NameFolded="" -- the first insert succeeded, the
// second violated the table's UNIQUE(name_folded) index. A single-row test
// (or two rows sharing one value) cannot distinguish "field preserved" from
// "field dropped but nothing collided" -- this needs >=2 rows with genuinely
// different values in the same uniquely-constrained column.
func TestRoundTrip_MultipleRowsWithJSONDashUniqueColumn(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Exec("CREATE UNIQUE INDEX uniq_roles_name_folded_test ON roles(name_folded)").Error)
	require.NoError(t, src.Create(&models.Role{Name: "Admin", NameFolded: "admin"}).Error)
	require.NoError(t, src.Create(&models.Role{Name: "Viewer", NameFolded: "viewer"}).Error)
	require.NoError(t, src.Create(&models.Role{Name: "Editor", NameFolded: "editor"}).Error)

	testModels := []any{&models.Role{}}
	var archive bytes.Buffer
	_, err := writeBackupModels(src, testModels, 5, "", testManifestKey(), nil, nil, &archive)
	require.NoError(t, err)

	stagingDir := t.TempDir()
	extractedManifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)

	dst := openTestDB(t)
	require.NoError(t, dst.Exec("CREATE UNIQUE INDEX uniq_roles_name_folded_test ON roles(name_folded)").Error)
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, extractedManifest, stagingDir)
	}), "restore must not fail with a UNIQUE constraint violation on a json:\"-\" column -- "+
		"each row's real, distinct name_folded value must be preserved, not dropped to \"\"")

	var roles []models.Role
	require.NoError(t, dst.Order("id ASC").Find(&roles).Error)
	require.Len(t, roles, 3)
	require.Equal(t, "admin", roles[0].NameFolded)
	require.Equal(t, "viewer", roles[1].NameFolded)
	require.Equal(t, "editor", roles[2].NameFolded)
}

// TestLoadArchive_RefusesDanglingReferenceInLoadedData is the mandatory,
// no-skip-flag enforcement design §3.4's corrected text requires: restore
// must refuse (and the transaction must roll back, leaving the target
// untouched) if the data it just loaded contains a reference to a row that
// doesn't exist.
func TestLoadArchive_RefusesDanglingReferenceInLoadedData(t *testing.T) {
	src := openTestDB(t)
	env := models.Environment{Name: "prod", ProjectID: 99999} // dangling on purpose -- no such project
	require.NoError(t, src.Create(&env).Error)

	testModels := []any{&models.Project{}, &models.Environment{}}
	var archive bytes.Buffer
	_, err := writeBackupModels(src, testModels, 1, "", testManifestKey(), nil, nil, &archive)
	require.NoError(t, err) // backup itself only WARNS (manifest.DanglingReferences), never refuses

	stagingDir := t.TempDir()
	manifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)
	require.Len(t, manifest.DanglingReferences, 1, "backup-time warning must have recorded it")

	dst := openTestDB(t)
	loadErr := dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	})
	require.Error(t, loadErr)
	require.Contains(t, loadErr.Error(), "dangling reference")

	var count int64
	require.NoError(t, dst.Model(&models.Environment{}).Count(&count).Error)
	require.Zero(t, count, "the transaction must have rolled back -- target left untouched")
}

// TestLoadArchive_RefusesUnrecognizedColumn is design §3.5's detection
// layer: a manifest table entry declaring a column the current model
// doesn't have (and that isn't on the known-removed allowlist) must refuse
// the whole restore rather than silently drop it.
func TestLoadArchive_RefusesUnrecognizedColumn(t *testing.T) {
	manifest := Manifest{
		FormatVersion: FormatVersion,
		Backend:       Backend,
		Tables: []TableEntry{
			{Name: "projects", TarName: "tables/projects.ndjson", RowCount: 0, Columns: []string{"id", "name", "a_column_that_was_renamed"}},
		},
	}
	stagingDir := t.TempDir()
	require.NoError(t, stageEmptyTableFile(t, stagingDir, "tables/projects.ndjson"))

	dst := openTestDB(t)
	err := dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "a_column_that_was_renamed")
}

func readStagedFile(t *testing.T, stagingDir, name string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(filepath.Join(stagingDir, name)) // #nosec G304 -- test-controlled path
}

func stageEmptyTableFile(t *testing.T, stagingDir, name string) error {
	t.Helper()
	return stageFile(stagingDir, name, nil)
}

// TestRoundTrip_PreservesSoftDeletedRows: a soft-deleted row (deleted_at set) is
// still a row. walkTable once used db.Model(model), whose default scope adds
// `deleted_at IS NULL`, so a backup silently dropped every soft-deleted
// project/environment/secret, and a restore then refused the archive because
// audit_events (append-only) still named the dropped project (#3164: the demo's
// GOLDEN-PATH s7 backup/restore failed with "dangling reference ... references
// missing projects.id=4" after check.sh deleted its scratch project).
func TestRoundTrip_PreservesSoftDeletedRows(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Create(&models.Project{Name: "live"}).Error)
	gone := models.Project{Name: "soft-deleted"}
	require.NoError(t, src.Create(&gone).Error)
	require.NoError(t, src.Delete(&gone).Error)

	testModels := []any{&models.Project{}, &models.Environment{}}
	key := testManifestKey()
	var archive bytes.Buffer
	_, err := writeBackupModels(src, testModels, 5, "", key, nil, nil, &archive)
	require.NoError(t, err)

	stagingDir := t.TempDir()
	extracted, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)

	dst := openTestDB(t)
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, extracted, stagingDir)
	}))

	var all []models.Project
	require.NoError(t, dst.Unscoped().Order("id ASC").Find(&all).Error)
	require.Len(t, all, 2, "the soft-deleted project must survive backup/restore")
	require.False(t, all[0].DeletedAt.Valid)
	require.True(t, all[1].DeletedAt.Valid, "deleted_at must be preserved, not cleared")
	require.Equal(t, gone.ID, all[1].ID)
}
