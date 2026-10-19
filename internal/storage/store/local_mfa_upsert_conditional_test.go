package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestUpsertMFASecret_NeverReplacesActivatedSecret (#2692) runs on SQLite and,
// when KEYORIX_TEST_PG_DSN is set, on Postgres: the two dialects render the
// conditional ON CONFLICT ... DO UPDATE ... WHERE and report its 0-row outcome
// independently, so each is checked on its own.
func TestUpsertMFASecret_NeverReplacesActivatedSecret(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		checkUpsertMFASecretConditional(t, newStoreS3(t, "mfa_upsert", &models.MFASecret{}))
	})
	t.Run("postgres", func(t *testing.T) {
		db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
		require.NoError(t, db.AutoMigrate(&models.MFASecret{}))
		checkUpsertMFASecretConditional(t, NewLocalStorage(db))
	})
}

func checkUpsertMFASecretConditional(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	get := func() models.MFASecret {
		var rows []models.MFASecret
		require.NoError(t, ls.db.Where("user_id = ?", 7).Find(&rows).Error)
		require.Len(t, rows, 1, "one secret row per user")
		return rows[0]
	}

	// Insert, then supersede a PENDING row: still allowed, and resets last_used_step.
	require.NoError(t, ls.UpsertMFASecret(ctx, &models.MFASecret{UserID: 7, SecretEnc: []byte("pending-1"), SecretMeta: []byte("m1")}))
	fresh, err := ls.MarkTOTPStepUsed(ctx, 7, 100)
	require.NoError(t, err)
	require.True(t, fresh)
	require.NoError(t, ls.UpsertMFASecret(ctx, &models.MFASecret{UserID: 7, SecretEnc: []byte("pending-2"), SecretMeta: []byte("m2")}))
	row := get()
	require.Equal(t, "pending-2", string(row.SecretEnc))
	require.Equal(t, "m2", string(row.SecretMeta))
	require.False(t, row.Activated)
	require.Nil(t, row.LastUsedStep, "a re-enrolment resets the anti-replay step, as UpdateAll did")

	// Activate, then a late enrolment: refused with the typed error, row untouched.
	matched, err := ls.ActivateMFASecret(ctx, 7, []byte("pending-2"))
	require.NoError(t, err)
	require.True(t, matched)
	err = ls.UpsertMFASecret(ctx, &models.MFASecret{UserID: 7, SecretEnc: []byte("attacker-seed"), SecretMeta: []byte("m3")})
	require.ErrorIs(t, err, storage.ErrMFASecretActivated)
	row = get()
	require.True(t, row.Activated, "#2692: an activated secret was replaced by a pending one")
	require.Equal(t, "pending-2", string(row.SecretEnc))
	require.Equal(t, "m2", string(row.SecretMeta))
}
