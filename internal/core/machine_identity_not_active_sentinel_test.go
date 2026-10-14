// machine_identity_not_active_sentinel_test.go — #2518, the core half.
//
// A no-longer-active owning machine identity is a DEFINITIVE deny, not a
// transient lookup failure. `CurrentMachineTokenRestriction`'s doc comment has
// always said so; until #2518 it returned a plain `fmt.Errorf`, which the auth
// middleware's cache-hit path could not distinguish from a storage blip, so it
// took the degrade-to-stale-snapshot branch and a suspended machine identity's
// token kept authenticating for up to validTokenTTL on every replica other than
// the one that ran the suspension (only that one flushes, via
// SetMachineTokenCacheFlusher).
//
// These tests assert the SENTINEL, not the message: errors.Is is what the
// caller actually branches on, and a string-matching test would pass while the
// caller still could not tell this condition apart from anything else. The
// middleware-side behaviour is
// server/middleware/cache_hit_transient_degrade_test.go's
// TestCacheHit_MachineIdentityInactive_IsDefinitiveNotTransient.
package core_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// newMachineStateWorld builds a real-storage install with one machine identity
// in the given state holding one live credential, and returns the core plus the
// raw token.
func newMachineStateWorld(t *testing.T, state string) (*core.KeyorixCore, string, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "mi.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.Role{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: state}).Error)

	const raw = "kx_machine_sentineltoken"
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.MachineIdentityCredential{
		ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hex.EncodeToString(sum[:]),
	}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), raw, db
}

// Every non-active state must produce the sentinel. Table-driven over the real
// states rather than just "suspended", because the condition in the code is
// `state != MachineActive` — a test covering one state would not notice a future
// state being special-cased out of it.
func TestCurrentMachineTokenRestriction_NonActiveIdentity_ReturnsSentinel(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"suspended", "revoked", "deprovisioned", "pending"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			c, raw, _ := newMachineStateWorld(t, state)

			_, err := c.CurrentMachineTokenRestriction(context.Background(), raw)

			require.Error(t, err)
			assert.ErrorIs(t, err, core.ErrMachineIdentityNotActive,
				"a %q machine identity must be reported as a DEFINITIVE deny the caller can branch on, "+
					"not an untyped error indistinguishable from a storage failure", state)
			assert.Contains(t, err.Error(), state,
				"the concrete state must stay in the message for logs")
			// The two existing sentinels describe the CREDENTIAL, not the
			// identity. Conflating them would make a caller that denies on
			// ErrMachineTokenRevoked report the wrong reason.
			assert.NotErrorIs(t, err, core.ErrMachineTokenRevoked)
			assert.NotErrorIs(t, err, core.ErrMachineTokenExpired)
		})
	}
}

// Calibration: an ACTIVE identity must still succeed. Without this, returning
// the sentinel unconditionally would pass the test above.
func TestCurrentMachineTokenRestriction_ActiveIdentity_Succeeds(t *testing.T) {
	t.Parallel()
	c, raw, _ := newMachineStateWorld(t, "active")

	_, err := c.CurrentMachineTokenRestriction(context.Background(), raw)
	require.NoError(t, err, "an active machine identity's live credential must resolve cleanly")
}

// Calibration, the other direction: a transient storage failure must NOT be
// reported as the sentinel, or the middleware's cache-hit path would start
// denying on blips — the exact inversion INV-MW-05 forbids. Produced by making
// the table unreadable, the same technique
// server/middleware/cache_hit_transient_degrade_test.go uses.
func TestCurrentMachineTokenRestriction_StorageFailure_IsNotTheSentinel(t *testing.T) {
	t.Parallel()
	c, raw, db := newMachineStateWorld(t, "active")
	require.NoError(t, db.Migrator().DropTable(&models.MachineIdentityCredential{}))

	_, err := c.CurrentMachineTokenRestriction(context.Background(), raw)

	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrMachineIdentityNotActive,
		"a storage failure is INDETERMINATE: reporting it as the definitive not-active deny would make "+
			"a storage blip log out every machine token on a cache hit")
	assert.NotErrorIs(t, err, core.ErrMachineTokenRevoked)
	assert.NotErrorIs(t, err, core.ErrMachineTokenExpired)
}

// The sibling path: ValidateMachineToken checks the same condition and now
// returns the same sentinel. Its callers deny on any error, so this is not
// load-bearing — but a sibling condition returning a differently-typed error is
// precisely how the cache-hit path came to be unable to see this one, so the two
// are pinned together.
func TestValidateMachineToken_NonActiveIdentity_ReturnsSameSentinel(t *testing.T) {
	t.Parallel()
	c, raw, _ := newMachineStateWorld(t, "suspended")

	_, _, _, _, err := c.ValidateMachineToken(context.Background(), raw)

	require.Error(t, err)
	assert.ErrorIs(t, err, core.ErrMachineIdentityNotActive,
		"ValidateMachineToken and CurrentMachineTokenRestriction check the identical condition and must "+
			"report it identically")
	require.True(t, errors.Is(err, core.ErrMachineIdentityNotActive))
}
