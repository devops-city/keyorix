// backup_restore_property_seed_test.go: a registry-driven "one row per
// model" seeder for the core property test (design-b3-backup-v2.md §11.1,
// backup_restore_property_test.go). Deliberately generic rather than a
// hand-written fixture per model: a model added to storage.AllModels() in
// the future must be covered automatically, without this file changing.
//
// Every cross-table reference field (backupfmt.ClassifiedFields()) is set to
// an already-inserted parent row's real ID, walking storage.AllModels() in
// backupfmt.RestoreOrder(). CreatedAt/UpdatedAt get an explicit,
// microsecond-truncated timestamp (GORM only auto-fills a field left at its
// zero value, and a raw time.Now() would carry nanosecond precision that
// Postgres's timestamp column silently truncates on insert -- harmless in
// itself, but it would make a Postgres-target row's re-backup hash disagree
// with the SQLite-source original for a reason that has nothing to do with a
// real data-loss bug). Every other field is left at its Go zero value: NOT
// NULL is satisfied trivially by a zero value (empty string, 0, false), and
// a UNIQUE index can't collide when this seeds exactly one row per table.
// propertySeedOverrides exists for the real exceptions a BeforeSave hook or
// DB-level CHECK constraint requires -- discovered by running this against a
// real database and reading what it reports, not guessed in advance.
package admin

import (
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/storage"
)

var propertySeedCounter atomic.Int64

// propertySeedBaseTime anchors every seeded CreatedAt/UpdatedAt -- fixed
// rather than time.Now() so a test failure is reproducible byte-for-byte,
// and pre-truncated to microseconds for the reason in this file's own doc
// comment above.
var propertySeedBaseTime = time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

// propertySeedOverride supplies an explicit value for one (model, field)
// pair the generic filler cannot safely derive -- the same override-table
// pattern internal/backupfmt/order.go's referenceOverrides uses, for the
// same reason: a short, explicit exception list beats a hand-maintained
// fixture per model.
type propertySeedOverride struct {
	Model, Field string
	Value        func(n int64) any
}

var propertySeedOverrides = []propertySeedOverride{}

func propertySeedOverrideValue(model, field string, n int64) (any, bool) {
	for _, o := range propertySeedOverrides {
		if o.Model == model && o.Field == field {
			return o.Value(n), true
		}
	}
	return nil, false
}

var deletedAtType = reflect.TypeFor[gorm.DeletedAt]()
var timeTimeType = reflect.TypeFor[time.Time]()

// setIntLikeField sets fv (a uint/int kind, or pointer to one) to id --
// used both for FK columns (id = the referenced parent's real primary key)
// and left untouched (id = 0, i.e. the Go zero value) for self-references
// and polymorphic non-references, matching this schema's established "0 =
// no reference" convention.
func setIntLikeField(fv reflect.Value, id int64) {
	if id == 0 {
		return // already the zero value
	}
	t := fv.Type()
	k := t.Kind()
	if k == reflect.Pointer {
		nv := reflect.New(t.Elem())
		setIntLikeField(nv.Elem(), id)
		fv.Set(nv)
		return
	}
	switch k {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fv.SetUint(uint64(id)) // #nosec G115 -- id is always a just-inserted test row's small autoincrement PK, never near int64/uint64 bounds
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fv.SetInt(id)
	}
}

// int64FromField reads back a uint/int-kind field (the primary key, after
// db.Create populates it) as an int64.
func int64FromField(fv reflect.Value) int64 {
	switch fv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(fv.Uint()) // #nosec G115 -- an autoincrement PK from this test's own tiny seeded tables, never near int64's bound
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fv.Int()
	default:
		return 0
	}
}

// seedOneRowPerModel creates exactly one row in every table
// storage.AllModels() defines, in backupfmt.RestoreOrder() so a
// cross-table reference field can be set to an already-inserted parent
// row's real ID. Returns the inserted primary-key ID for every model that
// has a single-column primary key (composite-PK join tables are never
// referenced by another table in this schema -- internal/backupfmt/order.go
// confirms this by construction -- so they're seeded but not recorded here).
func seedOneRowPerModel(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()

	order, err := backupfmt.RestoreOrder()
	require.NoError(t, err)

	byName := make(map[string]any, len(order))
	for _, m := range storage.AllModels() {
		byName[reflect.TypeOf(m).Elem().Name()] = m
	}

	classified, unresolved := backupfmt.ClassifiedFields()
	require.Empty(t, unresolved, "backupfmt.ClassifiedFields reports unresolved reference fields")
	type refInfo struct {
		refs             string
		selfOrNotRefOnly bool
	}
	refByModelField := make(map[[2]string]refInfo, len(classified))
	for _, c := range classified {
		// c.Refs == c.Model is a self-reference resolved via the naming
		// convention rather than the explicit selfReferences list (e.g.
		// MachineIdentity.CreatedByMachineIdentityID -> MachineIdentity) --
		// RestoreOrder's own graph builder already treats this the same way
		// (order.go: "self-reference by convention match, not flagged via
		// selfReferences"), so the seeder must too.
		selfByConvention := c.Refs == c.Model
		refByModelField[[2]string{c.Model, c.Field}] = refInfo{
			refs:             c.Refs,
			selfOrNotRefOnly: c.SelfRef || c.NotReference || selfByConvention,
		}
	}

	insertedID := make(map[string]int64, len(order))
	for _, modelName := range order {
		proto, ok := byName[modelName]
		require.True(t, ok, "model %s is in RestoreOrder but not AllModels", modelName)

		elemType := reflect.TypeOf(proto).Elem()
		v := reflect.New(elemType).Elem()

		for i := 0; i < elemType.NumField(); i++ {
			f := elemType.Field(i)
			if !f.IsExported() {
				continue
			}
			gormTag := f.Tag.Get("gorm")
			if gormTag == "-" || strings.HasPrefix(gormTag, "-:") {
				continue
			}
			if f.Name == "ID" {
				continue // auto-increment PK; GORM assigns it on Create
			}
			if f.Type == deletedAtType {
				continue // zero value = not soft-deleted, the correct default
			}

			n := propertySeedCounter.Add(1)

			if ov, ok := propertySeedOverrideValue(modelName, f.Name, n); ok {
				v.Field(i).Set(reflect.ValueOf(ov))
				continue
			}

			if f.Name == "CreatedAt" && f.Type == timeTimeType {
				v.Field(i).Set(reflect.ValueOf(propertySeedBaseTime.Add(time.Duration(n) * time.Microsecond)))
				continue
			}
			if f.Name == "UpdatedAt" && f.Type == timeTimeType {
				v.Field(i).Set(reflect.ValueOf(propertySeedBaseTime.Add(time.Duration(n)*time.Microsecond + time.Second)))
				continue
			}
			if f.Type == timeTimeType {
				// Any OTHER non-pointer time.Time field: give it a real,
				// fixed, modern timestamp too, rather than leaving it at
				// Go's zero value (0001-01-01). Found live via
				// TestBackupRestore_PropertyRoundTrip's Postgres->Postgres
				// direction: StatsSnapshot.SnapshotDate left at zero
				// round-tripped through Postgres's timestamptz (an absolute
				// UTC instant) and back into a LOCAL time.Time using this
				// process's zone database's pre-1900 Local Mean Time
				// offset for that date -- which this test observed
				// differing by tens of seconds between the source insert
				// and the post-restore insert of the SAME zero value, a
				// real but unrelated LMT/timezone-database quirk, not a
				// restore data-loss bug. A modern date has no such history.
				v.Field(i).Set(reflect.ValueOf(propertySeedBaseTime.Add(time.Duration(n)*time.Microsecond + 2*time.Second)))
				continue
			}

			if ref, ok := refByModelField[[2]string{modelName, f.Name}]; ok {
				if ref.selfOrNotRefOnly {
					continue // 0 / nil -- no parent, or a polymorphic field this schema has no single target for
				}
				parentID, ok := insertedID[ref.refs]
				require.True(t, ok, "model %s field %s references %s, which has no recorded inserted-row ID "+
					"(composite-PK join table referenced by another table? should not happen in this schema)",
					modelName, f.Name, ref.refs)
				setIntLikeField(v.Field(i), parentID)
				continue
			}
			// else: leave at the Go zero value.
		}

		instance := v.Addr().Interface()
		require.NoError(t, db.Create(instance).Error, "seed one row for model %s", modelName)

		if idField := v.FieldByName("ID"); idField.IsValid() {
			if id := int64FromField(idField); id != 0 {
				insertedID[modelName] = id
			}
		}
	}
	return insertedID
}
