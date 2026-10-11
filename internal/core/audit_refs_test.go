package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestFormatAuditRef(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "secret 3", formatAuditRef(auditKindSecret, 3, ""), "no name: the bare id form, unchanged from before")
	assert.Equal(t, `secret 3 ("db-pass")`, formatAuditRef(auditKindSecret, 3, "db-pass"))
	// A hostile name cannot start a new clause or a new line in the description.
	got := formatAuditRef(auditKindUser, 9, "x\" restored\nuser 1 (\"admin")
	assert.NotContains(t, got, "\n")
	assert.Equal(t, `user 9 ("x\" restored\nuser 1 (\"admin")`, got)
}

// New audit events name the object next to its id (DEMO-UI-2); a missing object degrades
// to the bare id instead of failing; and no secret VALUE is ever read to build the text.
func TestAuditDescriptionsCarryNames(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.UserRole{}, &models.GroupRole{}, &models.UserGroup{}, &models.Role{}, &models.Group{}, &models.User{},
		&models.ShareRecord{}, &models.SecretACL{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	lastDescription := func(eventType string) string {
		var ev models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", eventType).Order("id desc").First(&ev).Error, "expected a %s event", eventType)
		return ev.Description
	}

	t.Run("secret restored names the secret", func(t *testing.T) {
		require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: 999, ProjectID: 1, Name: "env"}).Error)
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 999, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteSecret(ctx, s.ID))
		require.NoError(t, c.RestoreSecret(ctx, 42, s.ID))
		assert.Equal(t, fmt.Sprintf(`secret %d ("db-password") restored`, s.ID), lastDescription("secret.restored"))
	})

	t.Run("project restored names the project", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "payments"})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteProject(ctx, p.ID))
		require.NoError(t, c.RestoreProject(ctx, 42, p.ID))
		assert.Contains(t, lastDescription("project.restored"), fmt.Sprintf(`project %d ("payments") restored`, p.ID))
	})

	t.Run("project deleted keeps the name read before the delete", func(t *testing.T) {
		c.LogProjectDeleted(ctx, 42, 77, "legacy", false)
		assert.Equal(t, `project 77 ("legacy") deleted (force=false)`, lastDescription("project.deleted"))
		c.LogProjectDeleted(ctx, 42, 78, "", true)
		assert.Equal(t, `project 78 deleted (force=true)`, lastDescription("project.deleted"))
	})

	t.Run("role assignment names role and user, group role names role and group", func(t *testing.T) {
		role := &models.Role{Name: "deployer"}
		require.NoError(t, db.Create(role).Error)
		user := &models.User{Username: "bob", Email: "bob@example.com"}
		require.NoError(t, db.Create(user).Error)
		group := &models.Group{Name: "platform"}
		require.NoError(t, db.Create(group).Error)

		c.LogRoleAssigned(ctx, 42, user.ID, role.ID, Scope{})
		assert.Equal(t, fmt.Sprintf(`role %d ("deployer") assigned to user %d ("bob")`, role.ID, user.ID), lastDescription(EventRoleAssigned))

		c.LogGroupRoleAssigned(ctx, 42, group.ID, role.ID, Scope{})
		assert.Equal(t, fmt.Sprintf(`role %d ("deployer") assigned to group %d ("platform")`, role.ID, group.ID), lastDescription(EventRoleGroupAssigned))

		c.LogGroupMemberAdded(ctx, 42, user.ID, group.ID)
		assert.Equal(t, fmt.Sprintf(`user %d ("bob") added to group %d ("platform")`, user.ID, group.ID), lastDescription(EventGroupMemberAdded))
	})

	t.Run("an unknown object degrades to the bare id", func(t *testing.T) {
		c.LogRoleAssigned(ctx, 42, 9001, 9002, Scope{})
		assert.Equal(t, "role 9002 assigned to user 9001", lastDescription(EventRoleAssigned))
	})

	t.Run("a schedule event names the secret (and only its name)", func(t *testing.T) {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "api-key", ProjectID: 1, EnvironmentID: 999, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		require.NoError(t, err)
		c.LogSecretScheduleSet(ctx, 42, s.ID)
		assert.Equal(t, fmt.Sprintf(`access schedule set for secret %d ("api-key")`, s.ID), lastDescription("secret.schedule_set"))
	})
}
