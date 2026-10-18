package store

// PERF-FIX-4: GetSecretScheduleAndLatestVersion must answer exactly what
// GetSecretAccessSchedule + GetLatestSecretVersion answer, in every state, and
// leave the read-path caches in a state those two methods accept.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newScheduleVersionTestStorage returns a caching LocalStorage on backend, and
// a function that opens another, independent LocalStorage (own pool on
// Postgres, own cache) on the same database.
func newScheduleVersionTestStorage(t *testing.T, backend string) (*LocalStorage, func() *LocalStorage) {
	t.Helper()
	if backend == "sqlite" {
		ls := newCacheTestStorage(t)
		return ls, func() *LocalStorage { return NewLocalStorage(ls.db) }
	}
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	return NewLocalStorage(db), func() *LocalStorage { return NewLocalStorage(pgOpen(t, dsn)) }
}

// stmtCounter counts the statements a *gorm.DB issues while on.
type stmtCounter struct {
	mu    sync.Mutex
	on    bool
	stmts []string
}

func countStatements(t *testing.T, db *gorm.DB, name string) *stmtCounter {
	t.Helper()
	c := &stmtCounter{}
	rec := func(db *gorm.DB) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.on {
			c.stmts = append(c.stmts, db.Statement.SQL.String())
		}
	}
	cb := db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register(name+":q", rec))
	require.NoError(t, cb.Row().After("gorm:row").Register(name+":row", rec))
	require.NoError(t, cb.Raw().After("gorm:raw").Register(name+":raw", rec))
	return c
}

func (c *stmtCounter) during(fn func()) []string {
	c.mu.Lock()
	c.on, c.stmts = true, nil
	c.mu.Unlock()
	fn()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.on = false
	return append([]string(nil), c.stmts...)
}

func requireSameSchedule(t *testing.T, want, got *models.SecretAccessSchedule, msg string) {
	t.Helper()
	if want == nil || got == nil {
		require.Equal(t, want == nil, got == nil, "%s: schedule presence", msg)
		return
	}
	require.Equal(t, want.ID, got.ID, msg)
	require.Equal(t, want.SecretNodeID, got.SecretNodeID, msg)
	require.Equal(t, want.AllowedDays, got.AllowedDays, msg)
	require.Equal(t, want.StartHour, got.StartHour, msg)
	require.Equal(t, want.EndHour, got.EndHour, msg)
	require.Equal(t, want.Timezone, got.Timezone, msg)
	require.True(t, want.CreatedAt.Equal(got.CreatedAt), "%s: created_at %v vs %v", msg, want.CreatedAt, got.CreatedAt)
	require.True(t, want.UpdatedAt.Equal(got.UpdatedAt), "%s: updated_at %v vs %v", msg, want.UpdatedAt, got.UpdatedAt)
	require.Equal(t, scheduleGenerationOf(want), scheduleGenerationOf(got), "%s: schedule generation", msg)
}

func requireSameVersionResult(t *testing.T, wantV *models.SecretVersion, wantErr error, gotV *models.SecretVersion, gotErr error, msg string) {
	t.Helper()
	if wantErr != nil {
		require.Error(t, gotErr, msg)
		require.Equal(t, wantErr.Error(), gotErr.Error(), msg)
		require.Equal(t, errors.Is(wantErr, storage.ErrSecretVersionNotFound), errors.Is(gotErr, storage.ErrSecretVersionNotFound), msg)
		require.Nil(t, gotV, msg)
		return
	}
	require.NoError(t, gotErr, msg)
	require.NotNil(t, gotV, msg)
	require.Equal(t, wantV.ID, gotV.ID, msg)
	require.Equal(t, wantV.VersionNumber, gotV.VersionNumber, msg)
	require.Equal(t, wantV.ReadCount, gotV.ReadCount, msg)
	require.Equal(t, wantV.EncryptedValue, gotV.EncryptedValue, msg)
	require.Equal(t, string(wantV.EncryptionMetadata), string(gotV.EncryptionMetadata), msg)
	require.True(t, wantV.CreatedAt.Equal(gotV.CreatedAt), msg)
}

// TestGetSecretScheduleAndLatestVersion_EquivalentToThePair walks one secret
// through every state and, in each, compares the combined read (cold, then
// warm, on a long-lived caching store) with GetSecretAccessSchedule +
// GetLatestSecretVersion on a fresh store.
func TestGetSecretScheduleAndLatestVersion_EquivalentToThePair(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ls, open := newScheduleVersionTestStorage(t, backend)
			ctx := context.Background()
			sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "sv", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
			require.NoError(t, err)
			version := 0
			addVersion := func() {
				version++
				_, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{
					SecretNodeID: sec.ID, VersionNumber: version, CreatedAt: time.Now(),
					EncryptedValue: []byte{byte(version), 0xA5}, EncryptionMetadata: models.JSON(`{"v":1}`),
				})
				require.NoError(t, err)
			}
			check := func(state string) {
				t.Helper()
				ref := open()
				wantSched, wantSchedErr := ref.GetSecretAccessSchedule(ctx, sec.ID)
				require.NoError(t, wantSchedErr, state)
				wantV, wantVErr := ref.GetLatestSecretVersion(ctx, sec.ID)
				for _, round := range []string{"cold-or-stale", "warm"} {
					got, err := ls.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
					require.NoError(t, err, state)
					requireSameSchedule(t, wantSched, got.Schedule, state+"/"+round)
					requireSameVersionResult(t, wantV, wantVErr, got.LatestVersion, got.LatestVersionErr, state+"/"+round)
					// The pair on the SAME store, after the combined read touched its caches.
					s2, err := ls.GetSecretAccessSchedule(ctx, sec.ID)
					require.NoError(t, err)
					requireSameSchedule(t, wantSched, s2, state+"/"+round+"/pair-after")
					v2, v2Err := ls.GetLatestSecretVersion(ctx, sec.ID)
					requireSameVersionResult(t, wantV, wantVErr, v2, v2Err, state+"/"+round+"/pair-after")
				}
			}

			check("no schedule, no versions")
			require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: sec.ID, AllowedDays: "1,2,3", StartHour: 8, EndHour: 18, Timezone: "Europe/Berlin"}))
			check("schedule, no versions")
			addVersion()
			check("schedule, one version")
			addVersion()
			addVersion()
			check("schedule, three versions")
			var v3 models.SecretVersion
			require.NoError(t, ls.db.Where("secret_node_id = ? AND version_number = ?", sec.ID, 3).First(&v3).Error)
			require.NoError(t, ls.IncrementSecretReadCount(ctx, v3.ID))
			check("read count moved")
			require.NoError(t, ls.db.Delete(&models.SecretVersion{}, v3.ID).Error)
			check("latest version deleted")
			require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC"}))
			check("schedule updated in place")
			require.NoError(t, ls.DeleteSecretAccessSchedule(ctx, sec.ID))
			check("schedule deleted")
			require.NoError(t, ls.db.Where("secret_node_id = ?", sec.ID).Delete(&models.SecretVersion{}).Error)
			check("every version deleted")
			require.NoError(t, ls.DeleteSecret(ctx, sec.ID))
			check("secret deleted")
			got, err := ls.GetSecretScheduleAndLatestVersion(ctx, sec.ID+1000)
			require.NoError(t, err)
			require.Nil(t, got.Schedule)
			require.ErrorIs(t, got.LatestVersionErr, storage.ErrSecretVersionNotFound)
		})
	}
}

// TestGetSecretScheduleAndLatestVersion_OneStatementAndSharedCaches: warm, the
// combined read is ONE statement; the entries it publishes are accepted by
// GetSecretAccessSchedule / GetLatestSecretVersion as warm hits (their own
// one-probe path), and the entries THEY publish are hits for it. That the
// schedule entry hits also proves the combined statement's updated_at scans to
// the same generation as GORM's own row read.
func TestGetSecretScheduleAndLatestVersion_OneStatementAndSharedCaches(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newScheduleVersionTestStorage(t, backend)
			counter := countStatements(t, ls.db, "perffix4_"+backend)
			ctx := context.Background()
			sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "sv", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
			require.NoError(t, err)
			_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: sec.ID, VersionNumber: 1, CreatedAt: time.Now()})
			require.NoError(t, err)
			require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC"}))

			cold := counter.during(func() {
				_, err := ls.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
				require.NoError(t, err)
			})
			require.Len(t, cold, 2, "cold: the combined statement plus the version row: %q", cold)
			warm := counter.during(func() {
				_, err := ls.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
				require.NoError(t, err)
			})
			require.Len(t, warm, 1, "warm: one statement: %q", warm)

			// Entries it published are hits for the two classic methods (one probe each).
			sched := counter.during(func() {
				s, err := ls.GetSecretAccessSchedule(ctx, sec.ID)
				require.NoError(t, err)
				require.NotNil(t, s)
			})
			require.Len(t, sched, 1, "GetSecretAccessSchedule after the combined read: one generation probe (a hit): %q", sched)
			require.NotContains(t, strings.ToLower(sched[0]), "order by", "a full-row read means the published schedule entry did not validate: %q", sched)
			ver := counter.during(func() {
				_, err := ls.GetLatestSecretVersion(ctx, sec.ID)
				require.NoError(t, err)
			})
			require.Len(t, ver, 1, "GetLatestSecretVersion after the combined read: one generation probe (a hit): %q", ver)

			// And the other way round, on a fresh store warmed by the classic pair.
			ls2 := NewLocalStorage(ls.db)
			_, err = ls2.GetSecretAccessSchedule(ctx, sec.ID)
			require.NoError(t, err)
			_, err = ls2.GetLatestSecretVersion(ctx, sec.ID)
			require.NoError(t, err)
			after := counter.during(func() {
				_, err := ls2.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
				require.NoError(t, err)
			})
			require.Len(t, after, 1, "combined read after the classic pair warmed the version cache: %q", after)
		})
	}
}

// TestGetSecretScheduleAndLatestVersion_TransactionScopedStoreNeverPublishes:
// inside WithTransaction the combined read sees the transaction's own
// uncommitted rows and publishes nothing to the shared cache.
func TestGetSecretScheduleAndLatestVersion_TransactionScopedStoreNeverPublishes(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "sv", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	sentinel := errors.New("rollback")
	require.ErrorIs(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: sec.ID, VersionNumber: 1, CreatedAt: time.Now()}); err != nil {
			return err
		}
		if err := tx.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC"}); err != nil {
			return err
		}
		got, err := tx.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
		require.NoError(t, err)
		require.NotNil(t, got.Schedule, "read-your-own-writes inside the transaction")
		require.NoError(t, got.LatestVersionErr)
		require.Equal(t, 1, got.LatestVersion.VersionNumber)
		return sentinel
	}), sentinel)
	_, ok := ls.secretMetaCache.getSchedule(sec.ID)
	require.False(t, ok, "a transaction-scoped read published a schedule entry")
	_, ok = ls.secretMetaCache.getVersion(sec.ID)
	require.False(t, ok, "a transaction-scoped read published a version entry")
	got, err := ls.GetSecretScheduleAndLatestVersion(ctx, sec.ID)
	require.NoError(t, err)
	require.Nil(t, got.Schedule, "rolled back")
	require.ErrorIs(t, got.LatestVersionErr, storage.ErrSecretVersionNotFound, "rolled back")
}

// TestGetSecretScheduleAndLatestVersion_ReadsEveryScheduleColumn: every
// persisted SecretAccessSchedule field is set to a non-zero value and must come
// back from the combined statement as GORM's own row read returns it. A new
// column on the model that scheduleAndVersionsSQL does not select fails here.
func TestGetSecretScheduleAndLatestVersion_ReadsEveryScheduleColumn(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	row := models.SecretAccessSchedule{SecretNodeID: 77, AllowedDays: "1,5", StartHour: 3, EndHour: 9, Timezone: "Asia/Tokyo"}
	require.NoError(t, ls.db.Create(&row).Error)
	var want models.SecretAccessSchedule
	require.NoError(t, ls.db.Where("secret_node_id = ?", 77).First(&want).Error)
	got, err := ls.GetSecretScheduleAndLatestVersion(ctx, 77)
	require.NoError(t, err)
	require.NotNil(t, got.Schedule)

	wv, gv := reflect.ValueOf(want), reflect.ValueOf(*got.Schedule)
	for i := 0; i < wv.NumField(); i++ {
		f := wv.Type().Field(i)
		w, g := wv.Field(i), gv.Field(i)
		require.Falsef(t, w.IsZero(), "fixture must set %s to a non-zero value (extend the fixture for a new field)", f.Name)
		if tw, ok := reflect.TypeAssert[time.Time](w); ok {
			require.Truef(t, tw.Equal(g.Interface().(time.Time)), "%s: %v vs %v", f.Name, tw, g.Interface())
			continue
		}
		require.Equalf(t, w.Interface(), g.Interface(), "%s is not read by the combined statement", f.Name)
	}
}
