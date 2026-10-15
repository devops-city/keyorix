package backupfmt

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"gorm.io/gorm"
)

// removedColumn names one (model, column) pair design §3.5 calls a
// "known-intentionally-removed" allowlist entry -- added deliberately
// alongside the migration that removed a column, so restore can tell
// "this column was deliberately dropped" apart from "this column was
// renamed or type-changed" (the hazard §3.5's additive-only migration
// convention exists to prevent, and this allowlist exists to detect if it
// ever happens anyway). Empty today: this codebase has never removed a
// column from a live model. TestLoadArchive_NoStaleRemovedColumnEntries
// keeps this list honest the same way order.go's exception tables are kept
// honest, once it has entries to check.
type removedColumn struct {
	Model  string
	Column string
}

var knownRemovedColumns = []removedColumn{}

// batchSize is CreateInBatches' group size for loading table rows -- a few
// hundred rows per INSERT, not one row at a time (design §7.3: "GORM's
// CreateInBatches is the natural fit").
const batchSize = 200

// checkSchemaDelta implements design §3.5's detection layer: any column
// TableEntry.Columns declares that is NEITHER a column the CURRENT model
// still has NOR on knownRemovedColumns for this model is refused -- a
// silent rename or type change (the one hazard additive-only migrations
// cannot themselves prevent, only make loud the first time it would
// matter) must never be misread as "column just isn't there."
func checkSchemaDelta(modelName string, currentColumns []string, archived TableEntry) error {
	current := make(map[string]bool, len(currentColumns))
	for _, c := range currentColumns {
		current[c] = true
	}
	removed := make(map[string]bool)
	for _, rc := range knownRemovedColumns {
		if rc.Model == modelName {
			removed[rc.Column] = true
		}
	}
	for _, col := range archived.Columns {
		if current[col] || removed[col] {
			continue
		}
		return fmt.Errorf("table %q (archive, model %s) has column %q, which this binary's current schema neither has "+
			"nor lists as a known, deliberately-removed column -- refusing rather than silently drop or "+
			"misinterpret what may be a renamed or type-changed column (design §3.5)", archived.Name, modelName, col)
	}
	return nil
}

// schemaEpochMetadataKey mirrors internal/storage's unexported
// schemaEpochMetadataKey constant ("schema_epoch") -- must stay byte-for-
// byte identical, since both read/write the exact same system_metadata row.
// Duplicated rather than imported: internal/backupfmt cannot reach
// internal/storage's unexported constant (server/admin's own
// auditHighWaterMetadataKey duplicates a sibling system_metadata key key for
// the identical reason).
//
// Why this needs special handling at all: migrateDatabase's
// recordSchemaEpoch (ADR-097) unconditionally upserts THIS key into
// system_metadata as its very last step, BEFORE LoadArchive ever runs (§3.4:
// migrations run first) -- so the target already has a schema_epoch row
// reflecting the CURRENT (restoring) binary's own epoch by the time loading
// starts. The archive's OWN schema_epoch row must never overwrite it: ADR-
// 097's whole invariant is that this value reflects "the binary that most
// recently migrated this database," not historical/portable data -- loading
// the archive's (possibly older) epoch here would make a fully-current-
// schema, freshly-migrated database falsely report an old epoch. Found
// live: a plain INSERT of the archive's system_metadata rows hit "UNIQUE
// constraint failed: system_metadata.key" on this exact row, via
// TestAdminBackupRestore_RoundTrip's real, full-registry restore -- every
// OTHER system_metadata key is genuinely historical/portable data (e.g. the
// audit high-water mark, already handled by Manifest.Checkpoint separately)
// and loads normally; recordSchemaEpoch is the ONLY migrateDatabase call
// site that seeds this table (confirmed by inspection), so this single,
// named exclusion is complete, not a guess.
//
// ADR-101 added a second key recordSchemaEpoch upserts in the SAME statement,
// schemaMinCompatibleEpochMetadataKey below: the compatibility floor of the
// schema the target's own migration just produced. It is skipped for the
// identical reason -- it describes the restoring binary's schema, not
// portable data -- and loading the archive's copy would also hit the same
// UNIQUE constraint. These two keys are the complete set recordSchemaEpoch
// writes.
const schemaEpochMetadataKey = "schema_epoch"

// schemaMinCompatibleEpochMetadataKey mirrors internal/storage's unexported
// constant of the same name (ADR-101) -- byte-for-byte, same reason as
// schemaEpochMetadataKey above.
const schemaMinCompatibleEpochMetadataKey = "schema_min_compatible_epoch"

// rolePermissionsGenerationMetadataKey mirrors internal/storage/store's
// rolePermissionsGenerationKey -- byte-for-byte, same reason as
// schemaEpochMetadataKey above.
//
// The row is the role->permission cache's generation: cache state, not
// portable data (any value works on a restored database, whose servers start
// with empty caches; it only has to change on every later write). Since #3259,
// triggers on permissions and role_permissions write it whenever either table
// is written -- loading those tables in this same transaction creates it in the
// target before (or after) system_metadata loads. So the archive's copy is
// inserted only when the target has none yet, and otherwise skipped (a plain
// INSERT hit the primary key, found by TestBackupRestore_PropertyRoundTrip).
const rolePermissionsGenerationMetadataKey = "role_permissions_generation"

// isTriggerMaintainedRowAlreadyPresent reports whether rowPtr is the
// system_metadata role_permissions_generation row and the target (db, the load
// transaction) already holds that key.
func isTriggerMaintainedRowAlreadyPresent(db *gorm.DB, tableName string, rowPtr reflect.Value) (bool, error) {
	if tableName != systemMetadataTableName {
		return false, nil
	}
	keyField := rowPtr.Elem().FieldByName("Key")
	if !keyField.IsValid() || keyField.Kind() != reflect.String || keyField.String() != rolePermissionsGenerationMetadataKey {
		return false, nil
	}
	var n int64
	if err := db.Table(systemMetadataTableName).Where("key = ?", rolePermissionsGenerationMetadataKey).Count(&n).Error; err != nil {
		return false, fmt.Errorf("check for the target's own %s row: %w", rolePermissionsGenerationMetadataKey, err)
	}
	return n > 0, nil
}

// systemMetadataTableName is SystemMetadata's GORM table name -- the one
// table loadTable applies the schemaEpochMetadataKey skip to.
const systemMetadataTableName = "system_metadata"

// loadTable reads stagingDir's staged NDJSON file for model (one line per
// row, JSON keyed by column name per design §3.3) and CreateInBatches-
// inserts every row into db, inside whatever transaction db already is.
// A row's JSON object may be missing a key the current model has -- that
// field is simply left at its Go zero value, which GORM omits from the
// INSERT when the column has its own DB-level default (design §8's
// version-skipping-upgrade mechanism: "a column the backup's schema didn't
// have yet simply takes its GORM-defined default on insert").
//
// The system_metadata table's own schema_epoch row is the one row this
// function ever deliberately skips inserting -- see schemaEpochMetadataKey's
// doc comment. Still counted toward total (the row WAS read and validated
// against the manifest's declared row count; it just isn't loaded), so the
// row-count sanity check below stays a check on "did the staged file match
// what was verified," not silently weakened by this one exclusion.
// isSystemMetadataSchemaEpochRow reports whether rowPtr (a freshly-decoded
// row for table tableName) is one of system_metadata's own schema_epoch /
// schema_min_compatible_epoch rows (the two recordSchemaEpoch writes) --
// via reflection on a "Key" field, not a models.SystemMetadata type
// assertion, so this package doesn't need to import internal/storage/models
// for one narrow check.
func isSystemMetadataSchemaEpochRow(tableName string, rowPtr reflect.Value) bool {
	if tableName != systemMetadataTableName {
		return false
	}
	keyField := rowPtr.Elem().FieldByName("Key")
	if !keyField.IsValid() || keyField.Kind() != reflect.String {
		return false
	}
	k := keyField.String()
	return k == schemaEpochMetadataKey || k == schemaMinCompatibleEpochMetadataKey
}

func loadTable(db *gorm.DB, model any, entry TableEntry, stagingDir string) (int64, error) {
	path := filepath.Join(stagingDir, entry.TarName)
	f, err := os.Open(path) // #nosec G304 -- entry.TarName is this package's own generated name, matched exactly against the manifest by ExtractArchive before staging
	if err != nil {
		return 0, fmt.Errorf("open staged table file %q: %w", entry.TarName, err)
	}
	defer f.Close() //nolint:errcheck

	elemType := reflect.TypeOf(model).Elem()
	batch := reflect.MakeSlice(reflect.SliceOf(elemType), 0, batchSize)
	var total int64

	flush := func() error {
		if batch.Len() == 0 {
			return nil
		}
		if err := db.CreateInBatches(batch.Interface(), batchSize).Error; err != nil {
			return fmt.Errorf("insert batch into %q: %w", entry.Name, err)
		}
		batch = reflect.MakeSlice(reflect.SliceOf(elemType), 0, batchSize)
		return nil
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<30) // one NDJSON line can legitimately be large (a big secret value); cap matches ExtractArchive's own per-entry ceiling
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		rowPtr := reflect.New(elemType)
		if err := unmarshalRow(line, rowPtr.Interface()); err != nil {
			return total, fmt.Errorf("decode row %d of %q: %w", total, entry.Name, err)
		}
		total++
		if isSystemMetadataSchemaEpochRow(entry.Name, rowPtr) {
			continue // schemaEpochMetadataKey's own doc comment explains why
		}
		if skip, err := isTriggerMaintainedRowAlreadyPresent(db, entry.Name, rowPtr); err != nil {
			return total, fmt.Errorf("table %q: %w", entry.Name, err)
		} else if skip {
			continue // rolePermissionsGenerationMetadataKey's doc comment explains why
		}
		batch = reflect.Append(batch, rowPtr.Elem())
		if batch.Len() >= batchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return total, fmt.Errorf("read staged table file %q: %w", entry.TarName, err)
	}
	if err := flush(); err != nil {
		return total, err
	}
	if total != entry.RowCount {
		return total, fmt.Errorf("table %q: read %d rows but the manifest declares %d -- "+
			"the staged file doesn't match what was verified", entry.Name, total, entry.RowCount)
	}
	return total, nil
}

// LoadArchive is restore's data-loading step (design §3.4, §3.5): for every
// model the CURRENT binary's registry defines, in RestoreOrder()'s
// derived sequence, checks that model's table against the manifest for a
// schema delta (§3.5), then loads its rows from the staged NDJSON file
// (§3.3) -- entirely inside ONE transaction (db must already be a
// transaction handle, e.g. from db.Transaction(...) or db.Begin()). A table
// in the CURRENT registry with no corresponding manifest entry is left
// empty (a model the source binary's schema didn't have yet -- §8's
// version-skipping-upgrade case, not an error). A manifest table entry with
// no corresponding CURRENT model is refused (a table this binary no longer
// knows how to load correctly is exactly the unrecognized-schema hazard
// §3.5 exists to catch, extended from columns to whole tables).
//
// After every table loads, runs CheckDanglingReferences against the
// now-loaded target (scoped to the tables actually present) and refuses --
// no flag to skip this -- if it finds anything: design §3.4's corrected
// text, the mandatory check that replaces the deferred-FK-constraint safety
// net a schema with real FK constraints would have had.
func LoadArchive(db *gorm.DB, manifest Manifest, stagingDir string) error {
	order, err := RestoreOrder()
	if err != nil {
		return fmt.Errorf("derive restore order: %w", err)
	}
	// Walk the restore order by NAME and look each model up by that name:
	// the name used for error messages and for knownRemovedColumns must
	// come from the same element as the model, never from a parallel slice
	// in a different (registry) order (#3086).
	byName := modelsByTypeName()

	archivedByTable := make(map[string]TableEntry, len(manifest.Tables))
	for _, te := range manifest.Tables {
		archivedByTable[te.Name] = te
	}
	usedArchiveTables := make(map[string]bool, len(manifest.Tables))

	var loadedModels []any
	for _, name := range order {
		m := byName[name]
		s, err := parseSchema(m)
		if err != nil {
			return fmt.Errorf("parse schema for %s: %w", name, err)
		}
		entry, ok := archivedByTable[s.Table]
		if !ok {
			continue // not in this archive -- a model newer than the source binary's schema (§8); leave empty
		}
		usedArchiveTables[s.Table] = true

		if err := checkSchemaDelta(name, s.DBNames, entry); err != nil {
			return err
		}
		if _, err := loadTable(db, m, entry, stagingDir); err != nil {
			return fmt.Errorf("load table %q: %w", entry.Name, err)
		}
		loadedModels = append(loadedModels, m)
	}

	for _, te := range manifest.Tables {
		if !usedArchiveTables[te.Name] {
			return fmt.Errorf("archive contains table %q, which this binary's current model registry does not "+
				"define -- refusing rather than silently drop an entire table's worth of data (design §3.5, "+
				"extended from columns to whole tables)", te.Name)
		}
	}

	dangling, err := CheckDanglingReferences(db, loadedModels)
	if err != nil {
		return fmt.Errorf("check dangling references in restored data: %w", err)
	}
	if len(dangling) > 0 {
		return fmt.Errorf("restore refuses: %d dangling reference(s) found in the loaded data (first: table %q "+
			"column %q row %d references missing %s.id=%d) -- design §3.4's mandatory post-load check, no "+
			"override flag", len(dangling), dangling[0].Table, dangling[0].Column, dangling[0].RowID, dangling[0].RefTable, dangling[0].MissingID)
	}
	return nil
}
