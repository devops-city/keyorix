// automigrate_altered_table_hazard_test.go — INV-STORAGE-07 (#2503).
//
// ADR-078 records a footgun: on Postgres, a full AutoMigrate against a table
// that already exists -- re-inspected in the same run, or hand-altered via
// db.Migrator()/raw ALTER -- failed with pgx "insufficient arguments" and made
// later information_schema existence checks unreliable. The mitigation was
// procedural ("never full-AutoMigrate an existing, column-altered table"),
// repeated at ~15 call sites in factory.go, with no structural check.
//
// Rather than structurally enforcing that rule, these tests guard the
// CONDITION the hazard depends on. The hazard was an upstream driver bug, and
// both directions were reproduced directly against Postgres 16 (2026-10-03):
//
//   - the tree just before 3ef72a78 (the RotationPolicy double-AutoMigrate
//     fix), on its own go.mod (gorm v1.30.0, gorm.io/driver/postgres v1.5.0,
//     pgx v5.5.5): a fresh migrateDatabase fails "insufficient arguments";
//   - the SAME tree with only gorm.io/driver/postgres bumped: v1.5.4 still
//     fails, v1.5.5 and every later version tried (v1.5.6/7/9/11, v1.6.0,
//     v1.6.3) succeed;
//   - current main with all 54 existence-gated AutoMigrate calls in
//     migrateDatabase ungated (every gated table full-AutoMigrated on every
//     boot, hand-altered ones included): three successive boots succeed.
//
// So the rule is not load-bearing on the current stack, and a structural
// check of it would guard a failure that can no longer happen. What CAN
// re-arm it is a driver downgrade, or a future driver/pgx regression. Hence:
//
//   - TestGormPostgresDriver_AtLeastAutoMigrateHazardFix (default CI): the
//     compiled-in gorm.io/driver/postgres is >= v1.5.5;
//   - TestAutoMigrate_ExistingAndHandAlteredTables_Postgres (pg-gated): the
//     hazard shapes themselves succeed against a real Postgres, so a
//     regression in a version ABOVE the floor is caught too.
//
// What this does NOT cover: whether the procedural rule's call-site comments
// in factory.go are still followed (they are left in place, harmless), and
// SQLite (the hazard was pgx-specific; SQLite never had it).
package storage

import (
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// autoMigrateHazardFixedDriver is the first gorm.io/driver/postgres release
// on which the ADR-078 hazard does not reproduce (v1.5.4 fails, v1.5.5 passes).
const autoMigrateHazardFixedDriver = "v1.5.5"

func TestGormPostgresDriver_AtLeastAutoMigrateHazardFix(t *testing.T) {
	t.Parallel()
	info, ok := debug.ReadBuildInfo()
	require.True(t, ok, "build info unavailable -- cannot determine the compiled-in gorm.io/driver/postgres version")

	var got string
	for _, dep := range info.Deps {
		if dep.Path == "gorm.io/driver/postgres" {
			got = dep.Version
			if dep.Replace != nil {
				got = dep.Replace.Version
			}
			break
		}
	}
	require.NotEmpty(t, got, "gorm.io/driver/postgres is not in this test binary's build info -- this guard can no longer see the driver it protects against")

	assert.True(t, semverAtLeast(got, autoMigrateHazardFixedDriver),
		"gorm.io/driver/postgres %s is below %s: the ADR-078 AutoMigrate/pgx \"insufficient arguments\" hazard reproduces on this version "+
			"(see this file's header). Upgrade the driver rather than relying on factory.go's procedural never-re-AutoMigrate rule.",
		got, autoMigrateHazardFixedDriver)
}

func TestSemverAtLeast(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v, floor string
		want     bool
	}{
		{"v1.5.5", "v1.5.5", true},
		{"v1.6.3", "v1.5.5", true},
		{"v1.5.10", "v1.5.5", true}, // numeric, not lexical
		{"v1.5.4", "v1.5.5", false},
		{"v1.4.99", "v1.5.5", false},
		{"v0.9.0", "v1.5.5", false},
		{"v2.0.0", "v1.5.5", true},
		{"v1.5.5-0.20250101000000-abcdef123456", "v1.5.5", false}, // pseudo-version before the tag
		{"(devel)", "v1.5.5", false},                              // unparseable fails closed
		{"", "v1.5.5", false},
	} {
		assert.Equal(t, c.want, semverAtLeast(c.v, c.floor), "semverAtLeast(%q, %q)", c.v, c.floor)
	}
}

// semverAtLeast reports whether v >= floor for plain vMAJOR.MINOR.PATCH
// versions. A pre-release or pseudo-version of the floor's own release is
// treated as below it; anything unparseable fails closed (false).
func semverAtLeast(v, floor string) bool {
	parse := func(s string) ([3]int, bool, bool) {
		var out [3]int
		s, ok := strings.CutPrefix(s, "v")
		if !ok {
			return out, false, false
		}
		core, _, hasPre := strings.Cut(s, "-")
		parts := strings.Split(core, ".")
		if len(parts) != 3 {
			return out, false, false
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return out, false, false
			}
			out[i] = n
		}
		return out, hasPre, true
	}
	got, gotPre, ok1 := parse(v)
	want, _, ok2 := parse(floor)
	if !ok1 || !ok2 {
		return false
	}
	for i := range 3 {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return !gotPre
}

// TestAutoMigrate_ExistingAndHandAlteredTables_Postgres reproduces the two
// hazard shapes ADR-078 and the factory.go comments describe, against a real
// Postgres, in one connection (the hazard was a prepared-statement-cache
// interaction, so it needs one connection reused across the steps):
//
//  1. re-inspecting a table AutoMigrate created earlier in the same run (the
//     3ef72a78 RotationPolicy shape);
//  2. full AutoMigrate on a table hand-altered via db.Migrator() and via raw
//     ALTER TABLE, after which tableExists/columnExists must still tell the
//     truth (the "spuriously return false" symptom).
func TestAutoMigrate_ExistingAndHandAlteredTables_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	// 1. Same-run re-inspection.
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}))
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}),
		"re-AutoMigrating a table created earlier in the same run must succeed (ADR-078 hazard, 3ef72a78)")

	// 2. Hand-altered tables, then full AutoMigrate.
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	require.NoError(t, db.Migrator().DropColumn(&models.Notification{}, "severity"))
	require.NoError(t, db.Migrator().AddColumn(&models.Notification{}, "Severity"))
	require.NoError(t, db.Exec("ALTER TABLE rotation_policies ADD COLUMN hand_altered_probe TEXT").Error)

	require.NoError(t, db.AutoMigrate(&models.Notification{}),
		"full AutoMigrate of a Migrator()-altered table must succeed (ADR-078 hazard)")
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}),
		"full AutoMigrate of a raw-ALTERed table must succeed (ADR-078 hazard)")

	assert.True(t, tableExists(db, "notifications"), "tableExists must not spuriously return false after re-AutoMigrate")
	assert.True(t, tableExists(db, "rotation_policies"))
	assert.True(t, columnExists(db, "notifications", "severity"), "columnExists must not spuriously return false after re-AutoMigrate")
	assert.True(t, columnExists(db, "rotation_policies", "hand_altered_probe"), "AutoMigrate must not drop a hand-added column")

	var n int64
	require.NoError(t, db.Model(&models.Notification{}).Count(&n).Error, "queries after re-AutoMigrate must still prepare")
	require.NoError(t, db.Model(&models.RotationPolicy{}).Count(&n).Error)
}
