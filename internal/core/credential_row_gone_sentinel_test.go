// credential_row_gone_sentinel_test.go — CRED-CACHE-REVOKE-1, the core half.
//
// A credential row that no longer exists is a DEFINITIVE deny, exactly like a
// revoked one. CurrentMachineTokenRestriction / CurrentPATRestriction used to
// pass the storage "not found" error through untyped, so the auth middleware's
// cache-hit path read it as indeterminate and kept serving the cached login on
// every replica that had not run the delete. The middleware-side, two-replica
// behaviour is server/http/credential_gone_cache_hit_test.go.
//
// The transient half (a storage failure is NOT the sentinel) is pinned for
// machine tokens by TestCurrentMachineTokenRestriction_StorageFailure_IsNotTheSentinel
// and for PATs below.
package core_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCurrentMachineTokenRestriction_RowGone_ReturnsRevokedSentinel(t *testing.T) {
	t.Parallel()
	for name, gone := range map[string]any{
		"credential-row": &models.MachineIdentityCredential{ID: 1},
		"identity-row":   &models.MachineIdentity{ID: 9},
	} {
		gone := gone
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, raw, db := newMachineStateWorld(t, "active")
			require.NoError(t, db.Delete(gone).Error)

			_, err := c.CurrentMachineTokenRestriction(context.Background(), raw)

			require.Error(t, err)
			assert.ErrorIs(t, err, core.ErrMachineTokenRevoked,
				"a vanished credential must be a definitive deny the cache-hit caller evicts on, not 'can't tell'")
		})
	}
}

func newPATWorld(t *testing.T) (*core.KeyorixCore, string, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "pat.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}))
	const raw = "kx_pat_rowgonetoken"
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.PersonalAccessToken{
		ID: 1, UserID: 7, Name: "t", TokenHash: hex.EncodeToString(sum[:]),
	}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), raw, db
}

// Calibration: the live row resolves cleanly, so the sentinel below is not
// returned unconditionally.
func TestCurrentPATRestriction_LiveRow_Succeeds(t *testing.T) {
	t.Parallel()
	c, raw, _ := newPATWorld(t)
	_, err := c.CurrentPATRestriction(context.Background(), raw)
	require.NoError(t, err)
}

func TestCurrentPATRestriction_RowGone_ReturnsRevokedSentinel(t *testing.T) {
	t.Parallel()
	c, raw, db := newPATWorld(t)
	require.NoError(t, db.Delete(&models.PersonalAccessToken{}, 1).Error)

	_, err := c.CurrentPATRestriction(context.Background(), raw)

	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrPATRevoked)
}

// The other direction: a storage failure stays indeterminate (INV-MW-05), so a
// blip does not log out every cached PAT.
func TestCurrentPATRestriction_StorageFailure_IsNotTheSentinel(t *testing.T) {
	t.Parallel()
	c, raw, db := newPATWorld(t)
	require.NoError(t, db.Migrator().DropTable(&models.PersonalAccessToken{}))

	_, err := c.CurrentPATRestriction(context.Background(), raw)

	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrPATRevoked)
	assert.NotErrorIs(t, err, core.ErrPATExpired)
}
