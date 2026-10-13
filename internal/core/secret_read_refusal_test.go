package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSecretReadRefusals_ClassifiedFromEveryGuard drives each read guard into its
// refusal on the real value-read paths (latest version, by version, metadata read
// with expiry) and checks ClassifySecretReadRefusal recognises it by sentinel, with
// the error's own text unchanged. INV-CORE-secret-read-refusal-sentinels.
func TestSecretReadRefusals_ClassifiedFromEveryGuard(t *testing.T) {
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour)

	cases := []struct {
		name  string
		setup func(t *testing.T, c *KeyorixCore, s *models.SecretNode)
		want  error
	}{
		{"expired", func(t *testing.T, c *KeyorixCore, s *models.SecretNode) {
			s.Expiration = &past
		}, ErrSecretExpired},
		{"suspended", func(t *testing.T, c *KeyorixCore, s *models.SecretNode) {
			s.Status = SecretStatusSuspended
		}, ErrSecretSuspended},
		{"max reads exhausted", func(t *testing.T, c *KeyorixCore, s *models.SecretNode) {
			one := 1
			s.MaxReads, s.ReadCount = &one, 1
		}, ErrSecretMaxReadsExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, db := newMaxReadsCore(t)
			s := &models.SecretNode{Name: "r", ProjectID: 1, EnvironmentID: 1, Type: "password", IsSecret: true, Status: "active"}
			tc.setup(t, c, s)
			require.NoError(t, db.Create(s).Error)
			require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v")}).Error)

			for name, read := range map[string]func() error{
				"latest":     func() error { _, err := c.GetSecretValue(ctx, s.ID); return err },
				"by version": func() error { _, err := c.GetSecretValueByVersion(ctx, s.ID, 1); return err },
			} {
				err := read()
				require.Errorf(t, err, "%s: the read must be refused", name)
				assert.Truef(t, errors.Is(err, tc.want), "%s: %v does not wrap %v", name, err, tc.want)
				ref, ok := ClassifySecretReadRefusal(err)
				require.Truef(t, ok, "%s: not classified: %v", name, err)
				assert.Equal(t, SecretReadRefusalState, ref.Kind)
				assert.NotContains(t, ref.Message, "%", "fixed message, no format verbs")
			}
		})
	}

	t.Run("outside access schedule", func(t *testing.T) {
		c, db := newMaxReadsCore(t)
		s := &models.SecretNode{Name: "r", ProjectID: 1, EnvironmentID: 1, Type: "password", IsSecret: true, Status: "active"}
		require.NoError(t, db.Create(s).Error)
		require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v")}).Error)
		require.NoError(t, db.Create(&models.SecretAccessSchedule{SecretNodeID: s.ID, AllowedDays: "*", StartHour: 0, EndHour: 0, Timezone: "UTC"}).Error)
		_, err := c.GetSecretValue(ctx, s.ID)
		ref, ok := ClassifySecretReadRefusal(err)
		require.Truef(t, ok, "not classified: %v", err)
		assert.Equal(t, SecretReadRefusalDenied, ref.Kind)
		assert.Equal(t, SecretReadRefusalCodeOutsideSchedule, ref.Code)
	})

	t.Run("expired secret via metadata read", func(t *testing.T) {
		c, db := newMaxReadsCore(t)
		s := &models.SecretNode{Name: "r", ProjectID: 1, EnvironmentID: 1, Type: "password", IsSecret: true, Status: "active", Expiration: &past}
		require.NoError(t, db.Create(s).Error)
		_, err := c.GetSecret(ctx, s.ID)
		assert.True(t, errors.Is(err, ErrSecretExpired), "GetSecret's expiry refusal: %v", err)
	})

	// A backward clock step is refused as "expired", indistinguishably.
	t.Run("clock regression is the expired refusal", func(t *testing.T) {
		c, db := newMaxReadsCore(t)
		future := time.Now().UTC().Add(24 * time.Hour)
		s := &models.SecretNode{Name: "r", ProjectID: 1, EnvironmentID: 1, Type: "password", IsSecret: true, Status: "active", Expiration: &future}
		require.NoError(t, db.Create(s).Error)
		require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v")}).Error)
		baseline := time.Now().UTC()
		c.now = func() time.Time { return baseline }
		_, err := c.GetSecretValue(ctx, s.ID)
		require.NoError(t, err)
		c.now = func() time.Time { return baseline.Add(-24 * time.Hour) }
		_, err = c.GetSecretValue(ctx, s.ID)
		require.Error(t, err)
		ref, ok := ClassifySecretReadRefusal(err)
		require.Truef(t, ok, "not classified: %v", err)
		assert.Equal(t, SecretReadRefusalCodeExpired, ref.Code)
	})

	// Not refusals: a storage failure enforcing max reads, and arbitrary errors.
	t.Run("non-refusals stay unclassified", func(t *testing.T) {
		for _, err := range []error{
			nil,
			errors.New("max-reads enforcement failed: database is locked"),
			errors.New("secret has expired"), // same text, no sentinel
		} {
			_, ok := ClassifySecretReadRefusal(err)
			assert.Falsef(t, ok, "%v must not be classified", err)
		}
	})
}
