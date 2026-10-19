// secret_version_contention_test.go — W3 (Session W, 2026-09-29): under sustained
// heavy concurrent writes to the SAME secret, updateSecretWithNewVersion's and
// storeNextSecretVersion's retry loops can legitimately exhaust
// maxRotateVersionAttempts (reproduced live at ~54% write-failure on Postgres and
// ~1% on SQLite at concurrency 50 against one secret). That is expected
// contention, not a server malfunction — this test pins the machine-checkable
// half of the fix: exhaustion must surface as the distinguishable
// ErrSecretVersionContentionExhausted sentinel (which the HTTP/gRPC layers map to
// 409/Aborted with a retry hint), not an indistinguishable generic error that
// falls through to a 500.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alwaysVersionConflictStorage wraps a real storage.Storage and makes every
// CreateSecretVersion call fail with the same "lost the race" error a real
// concurrent writer would produce — deterministically forcing
// updateSecretWithNewVersion/storeNextSecretVersion to exhaust their retry
// budget without needing actual concurrency.
func alwaysVersionConflictStorage(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		CreateSecretVersion: func(_ corestorage.Storage, ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
			return nil, corestorage.ErrDuplicateSecretVersion
		},
	})
}

// TestUpdateSecret_VersionContentionExhausted_IsDistinguishable: an UpdateSecret
// call that loses every version-number race must return an error that
// errors.Is-matches ErrSecretVersionContentionExhausted, not just a generic
// "exceeded N attempts" string a caller can only recognize by substring-matching.
func TestUpdateSecret_VersionContentionExhausted_IsDistinguishable(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "version-contention-test", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "contended-secret", ProjectID: proj.ID, EnvironmentID: envs[0].ID, Type: "generic",
		IsSecret: true, Status: "active",
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v1-value"),
	})
	require.NoError(t, err)

	c.storage = alwaysVersionConflictStorage(c.storage)

	_, err = c.UpdateSecret(ctx, &UpdateSecretRequest{ID: secret.ID, Value: []byte("v2-value"), UpdatedBy: "tester"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretVersionContentionExhausted),
		"exhausting the version-number retry loop must produce a distinguishable sentinel, not just an opaque error string: %v", err)
}

// TestRotateSecret_VersionContentionExhausted_IsDistinguishable is the same
// proof for RotateSecret's storeNextSecretVersion path (shared by
// RotateSecretOnDemand and RollbackSecret).
func TestRotateSecret_VersionContentionExhausted_IsDistinguishable(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "rotate-contention-test", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "contended-rotate-secret", ProjectID: proj.ID, EnvironmentID: envs[0].ID, Type: "generic",
		IsSecret: true, Status: "active",
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v1-value"),
	})
	require.NoError(t, err)

	c.storage = alwaysVersionConflictStorage(c.storage)

	_, err = c.RotateSecret(ctx, secret.ID, []byte("rotated-value"), 0, "tester")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretVersionContentionExhausted),
		"exhausting the version-number retry loop must produce a distinguishable sentinel: %v", err)
}
