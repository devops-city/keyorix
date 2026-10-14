package store

// credential_owner_refusal_test.go — #2701, the "sweep committed first" ordering.
//
// The race tests (internal/core/concurrency_credential_under_suspend_*_test.go)
// force a sweep into the window before a credential insert. This pins the other
// side deterministically, with no concurrency: once a sweep's state change has
// committed — the owner suspended, deprovisioned, deactivated or soft-deleted —
// every credential insert (CreatePersonalAccessToken, CreateSession,
// RotateSession) must refuse and leave NO row behind. That is the
// requireLiveCredentialOwner re-check on its own; on SQLite, where BEGIN
// IMMEDIATE serializes the insert transaction against the sweep, it is the only
// thing standing between "sweep committed before the insert transaction began"
// and a credential minted for a blocked owner.
//
// Positive controls run alongside: every login-capable state must still mint,
// so this cannot pass by refusing everything.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func TestCredentialInsertRefusedForUnusableOwner(t *testing.T) {
	type owner struct {
		name string
		// prepare puts user id into the state under test (or removes it).
		prepare func(t *testing.T, ls *LocalStorage, id uint)
		live    bool
	}
	setState := func(state string, active bool) func(*testing.T, *LocalStorage, uint) {
		return func(t *testing.T, ls *LocalStorage, id uint) {
			require.NoError(t, ls.db.Model(&models.User{}).Where("id = ?", id).
				Updates(map[string]any{"account_state": state, "is_active": active}).Error)
		}
	}
	owners := []owner{
		{"active", setState("active", true), true},
		{"pending_first_login", setState("pending_first_login", true), true},
		{"password_reset_required", setState("password_reset_required", true), true},
		{"suspended", setState("suspended", true), false},
		{"deprovisioned", setState("deprovisioned", true), false},
		{"is_active=false", setState("active", false), false},
		{"unrecognized_state", setState("bogus", true), false},
		{"soft_deleted", func(t *testing.T, ls *LocalStorage, id uint) {
			require.NoError(t, ls.DeleteUser(context.Background(), id))
		}, false},
		{"missing", func(t *testing.T, ls *LocalStorage, id uint) {
			require.NoError(t, ls.db.Unscoped().Where("id = ?", id).Delete(&models.User{}).Error)
		}, false},
	}

	type insert struct {
		name string
		// do mints one credential for id and returns a counter of the
		// credential rows for id that a successful mint would have added, plus the error.
		do func(t *testing.T, ls *LocalStorage, id uint) (func() int64, error)
	}
	ctx := context.Background()
	inserts := []insert{
		{"CreatePersonalAccessToken", func(t *testing.T, ls *LocalStorage, id uint) (func() int64, error) {
			_, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
				UserID: id, Name: "ci", TokenHash: fmt.Sprintf("h-%d", id), TokenPrefix: "kx_pat_x",
			})
			return func() int64 { return countRows(t, ls.db, &models.PersonalAccessToken{}, "user_id = ?", id) }, err
		}},
		{"CreateSession", func(t *testing.T, ls *LocalStorage, id uint) (func() int64, error) {
			_, err := ls.CreateSession(ctx, &models.Session{UserID: id, SessionToken: fmt.Sprintf("s-%d", id)})
			return func() int64 { return countRows(t, ls.db, &models.Session{}, "user_id = ?", id) }, err
		}},
		{"RotateSession", func(t *testing.T, ls *LocalStorage, id uint) (func() int64, error) {
			// The session being rotated was minted while its owner was live:
			// insert it directly so the owner's current state does not matter.
			old := &models.Session{UserID: id, SessionToken: hashSessionToken(fmt.Sprintf("old-%d", id)), FamilyID: "fam"}
			require.NoError(t, ls.db.Create(old).Error)
			_, _, err := ls.RotateSession(ctx, old.ID,
				&models.Session{UserID: id, SessionToken: fmt.Sprintf("new-%d", id), FamilyID: "fam"}, time.Now().UTC())
			return func() int64 {
				return countRows(t, ls.db, &models.Session{}, "user_id = ? AND id <> ?", id, old.ID)
			}, err
		}},
	}

	for _, ins := range inserts {
		for _, o := range owners {
			t.Run(ins.name+"/"+o.name, func(t *testing.T) {
				ls := freshCredentialStore(t)
				const id = 1
				o.prepare(t, ls, id)

				count, err := ins.do(t, ls, id)
				if o.live {
					require.NoError(t, err, "a login-capable owner (%s) must still be able to mint", o.name)
					assert.Equal(t, int64(1), count(), "the minted credential must be stored")
					return
				}
				assert.Error(t, err, "minting for a %s owner must be refused", o.name)
				assert.Zero(t, count(),
					"a refused mint must leave no credential row behind for a %s owner — the "+
						"insert and the owner re-check share one transaction", o.name)
			})
		}
	}
}

// freshCredentialStore is a private in-memory SQLite store with the user and
// credential tables, and an active user 1 (seedCredentialOwners).
func freshCredentialStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}))
	seedCredentialOwners(t, db)
	return NewLocalStorage(db)
}

func countRows(t *testing.T, db *gorm.DB, model any, where string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Unscoped().Model(model).Where(where, args...).Count(&n).Error)
	return n
}
