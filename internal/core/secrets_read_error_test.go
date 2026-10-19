// secrets_read_error_test.go — deterministic unit tests for
// docs/findings/2026-09-23-FINDING-update-secret-read-error-swallowed.md:
// updateSecretWithNewVersion (formerly storeNextSecretVersion) and CreateSecret's
// duplicate-name pre-check each read storage before deciding "not found", and
// previously could not distinguish that from a real read failure.
// FuzzStorageFaultOperations found this for the version-number read
// (testdata/fuzz/FuzzStorageFaultOperations/1fefa95ddd2b26bb, replayed by
// server/faultops); this file covers the same class deterministically, including
// the CreateSecret sibling the fuzzer never reached (GetSecretByName is not itself
// covered by that harness's fault-injection surface for this operation).
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretReadErrStub wraps a real storage.Storage and overrides exactly one
// read method at a time to inject a fixed error, mirroring the
// webauthnStorageErrStub / userRoleScopesStub pattern used elsewhere in this
// package for the same reason (MockStorage's fixed stubs can't be made to
// fail via mock.Called()).
func secretReadErrStub(inner corestorage.Storage, latestVersionErr error, getByNameErr error) corestorage.Storage {
	return hooked(inner, &storeHooks{
		GetLatestSecretVersion: func(next corestorage.Storage, ctx context.Context, secretID uint) (*models.SecretVersion, error) {
			if latestVersionErr != nil {
				return nil, latestVersionErr
			}
			return next.GetLatestSecretVersion(ctx, secretID)
		},
		GetSecretByName: func(next corestorage.Storage, ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
			if getByNameErr != nil {
				return nil, getByNameErr
			}
			return next.GetSecretByName(ctx, name, projectID, environmentID)
		},
	})
}

// TestUpdateSecret_LatestVersionReadErrorPropagates: a real (non-not-found)
// GetLatestSecretVersion failure inside updateSecretWithNewVersion must abort the
// update, not silently default to version 1 and overwrite whatever version
// happens to already occupy that slot.
func TestUpdateSecret_LatestVersionReadErrorPropagates(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "read-error-test", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: envs[0].ID, Type: "password",
		IsSecret: true, Status: "active",
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v1-value"),
	})
	require.NoError(t, err)

	wantErr := errors.New("db down")
	c.storage = secretReadErrStub(c.storage, wantErr, nil)

	_, err = c.UpdateSecret(ctx, &UpdateSecretRequest{ID: secret.ID, Value: []byte("v2-value"), UpdatedBy: "tester"})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)

	// The stub only breaks the read; verify directly against the real
	// underlying storage that no second version was written under the read
	// failure — a silent default-to-version-1 would otherwise either clobber
	// version 1's row or violate uniq_secret_versions_node_version, either way
	// leaving a mismatch between "reported error" and "what actually happened".
	versions, err := st.GetSecretVersions(ctx, secret.ID)
	require.NoError(t, err)
	assert.Len(t, versions, 1, "a real read failure must not produce a second version row")
}

// TestCreateSecret_DuplicateNameCheckReadErrorPropagates: a real (non-not-
// found) GetSecretByName failure in CreateSecret's duplicate-name pre-check
// must abort creation, not silently assume "no duplicate" and create a
// possibly-colliding secret.
func TestCreateSecret_DuplicateNameCheckReadErrorPropagates(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := c.CreateProject(ctx, "dup-check-read-error-test", "")
	require.NoError(t, err)
	envs, err := st.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	wantErr := errors.New("db down")
	c.storage = secretReadErrStub(c.storage, nil, wantErr)

	_, err = c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "new-secret", Value: []byte("value"), ProjectID: proj.ID, EnvironmentID: envID,
		Type: "generic", CreatedBy: "tester",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)

	// Confirm directly against real storage that nothing got created under the
	// read failure.
	normalized, nerr := identity.NewAddressName("new-secret")
	require.NoError(t, nerr)
	_, getErr := st.GetSecretByName(ctx, normalized.String(), proj.ID, envID)
	require.Error(t, getErr, "a real read failure during the duplicate check must not let a create through")
	assert.True(t, corestorage.IsSecretNotFound(getErr), "the real storage's own answer is 'not found' — confirms CreateSecret's failure was the injected error, not a second real absence")
}
