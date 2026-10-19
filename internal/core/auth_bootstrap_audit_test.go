package core

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bootstrapCoreWithAudit is freshBootstrapCore plus the audit table, so audit
// writes land somewhere the test can read them.
func bootstrapCoreWithAudit(t *testing.T) storage.Storage {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{}, &models.AuditEvent{},
	))
	return store.NewLocalStorage(db)
}

func bootstrapAuditEvents(t *testing.T, st storage.Storage) []*models.AuditEvent {
	t.Helper()
	evs, _, err := st.GetAuditLogs(context.Background(), &storage.AuditFilter{
		Actions: []string{EventUserCreated, EventProjectCreated},
	})
	require.NoError(t, err)
	return evs
}

// TestBootstrapSystem_AuditOnlyAfterCommit: a bootstrap that fails and rolls
// back must leave NO user.created / project.created event (a false success in
// the audit trail); the retry that succeeds writes exactly one of each, naming
// the real committed user and project. Session P, 2026-09-29.
func TestBootstrapSystem_AuditOnlyAfterCommit(t *testing.T) {
	for _, step := range []string{"AssignRole", "CreateProject", "SetSystemMetadata"} {
		t.Run(step, func(t *testing.T) {
			st := bootstrapCoreWithAudit(t)
			armed := true
			c := NewKeyorixCore(failOnceStorage(st, step, &armed))
			c.SetBootstrapToken(retryToken)
			ctx := context.Background()

			_, err := c.BootstrapSystem(ctx, goodRetryReq())
			require.Error(t, err)
			require.False(t, armed)
			assert.Empty(t, bootstrapAuditEvents(t, st), "a rolled-back bootstrap must not be audited as a success")

			res, err := c.BootstrapSystem(ctx, goodRetryReq())
			require.NoError(t, err)
			evs := bootstrapAuditEvents(t, st)
			byType := map[string][]*models.AuditEvent{}
			for _, e := range evs {
				byType[e.EventType] = append(byType[e.EventType], e)
			}
			require.Len(t, byType[EventUserCreated], 1, "exactly one user.created")
			require.Len(t, byType[EventProjectCreated], 1, "exactly one project.created")
			assert.True(t, strings.Contains(byType[EventUserCreated][0].Description, fmt.Sprintf("created user %d ", res.User.ID)),
				"user.created must name the committed user id, got %q", byType[EventUserCreated][0].Description)
			require.NotNil(t, byType[EventProjectCreated][0].ProjectID)
			assert.Equal(t, res.Project.ID, *byType[EventProjectCreated][0].ProjectID)
		})
	}
}
