package handlers

// #3508: DeleteSecret reads the purge date back AFTER the soft-delete and its secret.deleted
// audit row committed. A returned error from that read-back is tolerated (the header is
// omitted); a PANIC in it must be too, instead of escaping and aborting the request of a
// delete that already happened.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

var errReadbackPanic = errors.New("injected GetSecretIncludingDeleted panic")

func TestDeleteSecret_PurgeAtReadbackFault_DoesNotUndoCompletedDelete(t *testing.T) {
	for name, kind := range map[string]faultstorage.FaultKind{"panic": faultstorage.KindPanic, "error": faultstorage.KindError} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, i18n.InitializeForTesting())
			db := sqlitetest.Open(t, "kxhandlers_3508_")
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1)
			require.NoError(t, db.AutoMigrate(
				&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
				&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
				&models.Project{}, &models.Environment{}, &models.SecretNode{},
				&models.AuditEvent{}, &models.SecretVersion{}, &models.SecretAccessLog{},
				&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.SecretAccessSchedule{},
			))
			require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-s15", AccountState: "active"}).Error)
			adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
			require.NoError(t, db.Create(adminRole).Error)
			require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)
			require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-3508"}).Error)
			require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-3508"}).Error)

			fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
			cs := core.NewKeyorixCore(fs)
			h, err := NewSecretHandler(cs)
			require.NoError(t, err)
			secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
				Name: "readback-target", Value: []byte("s3cr3t"), ProjectID: 1, EnvironmentID: 10,
				Type: "static", CreatedBy: "alice-s15", OwnerID: 1,
			})
			require.NoError(t, err)

			fs.Arm(&faultstorage.FaultSpec{Method: "GetSecretIncludingDeleted", NthCall: 1, Kind: kind, Err: errReadbackPanic})

			r := withAdminCtxS15(withChiParam(
				httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
				"id", fmt.Sprintf("%d", secret.ID),
			))
			w := httptest.NewRecorder()
			require.NotPanics(t, func() { h.DeleteSecret(w, r) },
				"a panic in the post-commit purge-date read-back must not escape the handler")

			assert.Equal(t, http.StatusNoContent, w.Code, "the delete completed, so the answer is the normal 204")
			assert.Empty(t, w.Header().Get(purgeAtHeader), "purge date omitted when it could not be read back")

			var deleted int64
			require.NoError(t, db.Raw("SELECT COUNT(*) FROM secret_nodes WHERE id = ? AND deleted_at IS NOT NULL", secret.ID).Row().Scan(&deleted))
			assert.EqualValues(t, 1, deleted, "the secret is soft-deleted")
			var audited int64
			require.NoError(t, db.Raw("SELECT COUNT(*) FROM audit_events WHERE event_type = ?", "secret.deleted").Row().Scan(&audited))
			assert.EqualValues(t, 1, audited, "and the secret.deleted audit row is committed")
		})
	}
}
