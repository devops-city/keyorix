package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Regression (#289, HIGH): POST /projects/{id}/environments/{envId}/copy-secrets must
// require secrets.read on the SOURCE environment, exactly like the single-secret
// POST /secrets/{id}/copy route does — otherwise a principal deliberately scoped with
// secrets.write only (a "CI provisioner" role, specifically denied read so a leaked
// token can't be used to view existing secret VALUES) could use the bulk-copy endpoint
// to duplicate a secret it owns into an environment it can read, exfiltrating the value
// without ever holding secrets.read on the source.
func TestCopyEnvironmentSecretsRequiresSourceRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SecretAccessSchedule{},
	))

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "staging"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "production"}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "writer", Email: "w@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "reader-writer", Email: "rw@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)

	// A deliberately write-only "CI provisioner" role: secrets.write at project scope,
	// with secrets.read specifically withheld. And a second role holding both, to prove
	// the fix doesn't over-restrict a legitimately-scoped copy.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "ci-writer"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "ci-reader-writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error) // ci-writer: write only
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error) // ci-reader-writer: write
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 2}).Error) // + read

	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 1}).Error)

	// Note: token literals are hashed and cached in the process-wide auth token cache
	// (server/middleware/auth.go's tokenCache) keyed only by the token string, with no
	// per-test/per-DB scoping. Reusing a generic literal like "copyenv-writer-tok" that another
	// test file in this package also seeds (for a differently-permissioned user, in an
	// unrelated in-memory DB) risks that later test observing THIS test's stale cached
	// auth result. Use names unique to this test to avoid any cross-test collision.
	seedSession(t, db, 1, "copyenv-writer-tok")
	seedSession(t, db, 2, "copyenv-reader-writer-tok")

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	// Both users own a secret in the source (staging) environment — ownership alone is
	// NOT sufficient to bypass the RBAC read gate this test defends.
	_, err = coreService.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "writer-secret", Value: []byte("supersecret1"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "writer", OwnerID: 1,
	})
	require.NoError(t, err)
	_, err = coreService.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "rw-secret", Value: []byte("supersecret2"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "reader-writer", OwnerID: 2,
	})
	require.NoError(t, err)

	router, err := NewRouter(&config.Config{}, coreService)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	copySecrets := func(token string) int {
		req, err := http.NewRequest("POST", server.URL+"/api/v1/projects/1/environments/1/copy-secrets",
			strings.NewReader(`{"target_environment_id":2}`))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// The fix: secrets.write alone (no secrets.read on the source) is rejected — a
	// write-only-scoped, secret-owning principal can no longer use the bulk copy to
	// exfiltrate the value into an environment it can read.
	assert.Equal(t, http.StatusForbidden, copySecrets("copyenv-writer-tok"),
		"secrets.write without secrets.read on the source environment must be denied")

	// A principal holding secrets.read on the source (in addition to secrets.write) may
	// still perform the copy — the fix must not over-restrict the legitimate case.
	assert.Equal(t, http.StatusOK, copySecrets("copyenv-reader-writer-tok"),
		"secrets.write + secrets.read on the source environment must still succeed")
}
