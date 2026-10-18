package core

import (
	"context"
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

// Restore operations must be audited (the inverse of the delete events), so a
// soft-deleted secret/project/environment reappearing leaves a trail.
func TestRestoreOperationsAudit(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.UserRole{}, &models.GroupRole{}, &models.UserGroup{}, &models.Role{}, &models.Group{},
		// #370: DeleteSecret revokes ShareRecord rows in the same transaction as the
		// secret's own soft-delete.
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	auditActor := func(eventType string) *uint {
		var ev models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", eventType).First(&ev).Error, "expected a %s event", eventType)
		return ev.UserID
	}

	t.Run("secret.restored", func(t *testing.T) {
		// A live parent project + environment: RestoreSecret refuses to restore into a
		// soft-deleted parent, so the audit test needs them present and live.
		require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: 999, ProjectID: 1, Name: "env"}).Error)
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "k", ProjectID: 1, EnvironmentID: 999, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteSecret(ctx, s.ID))
		require.NoError(t, c.RestoreSecret(ctx, 42, s.ID))
		require.NotNil(t, auditActor("secret.restored"))
		assert.Equal(t, uint(42), *auditActor("secret.restored"))
	})

	t.Run("project.restored", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj"})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteProject(ctx, p.ID))
		require.NoError(t, c.RestoreProject(ctx, 42, p.ID))
		require.NotNil(t, auditActor("project.restored"))
	})

	// #311: the project.restored event must itemize what the cascade actually
	// resurrected (a per-type count), and that count must correctly EXCLUDE a
	// secret that was soft-deleted independently, before (and unrelated to) the
	// project's own deletion — otherwise a DR-test or accidental delete-then-undo
	// of a whole project leaves no way to tell "1 secret came back" from "200",
	// nor whether an unrelated, deliberately-retired secret was among them.
	//
	// Correlation-window reasoning: DeleteProject stamps the project and every
	// then-LIVE child with ONE uniform deleted_at (the "cascade timestamp").
	// RestoreProject reads that timestamp back off the project row and only
	// restores children whose deleted_at >= it. A secret already soft-deleted
	// BEFORE the project (an earlier, independent recycle-bin delete — e.g. an
	// operator remediating a compromised secret) carries a strictly earlier
	// deleted_at and is correctly left alone. There is no coherent "deleted AFTER
	// the project" case to test: DeleteSecret's soft-delete only matches
	// currently-live rows, and a project's live secrets are exactly what the
	// cascade already swept up, so nothing stays independently deletable once the
	// project itself is gone.
	t.Run("project.restored itemizes the cascade and excludes independent deletes", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj-itemized"})
		require.NoError(t, err)
		_, err = c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
		require.NoError(t, err)

		kept, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			ProjectID: p.ID, EnvironmentID: 1, Name: "kept", IsSecret: true, Type: "text", Status: "active",
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		retired, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			ProjectID: p.ID, EnvironmentID: 1, Name: "retired", IsSecret: true, Type: "text", Status: "active",
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)

		// "retired" was deliberately soft-deleted well before the project — an
		// operator's own remediation, independent of any project-level action.
		require.NoError(t, db.Unscoped().Model(&models.SecretNode{}).
			Where("id = ?", retired.ID).Update("deleted_at", time.Now().Add(-time.Hour)).Error)

		require.NoError(t, c.storage.DeleteProject(ctx, p.ID))
		require.NoError(t, c.RestoreProject(ctx, 42, p.ID))

		// "kept" (swept up by the cascade) is live again; "retired" (independently
		// deleted earlier) stays in the recycle bin.
		_, err = c.storage.GetSecret(ctx, kept.ID)
		require.NoError(t, err)
		_, err = c.storage.GetSecret(ctx, retired.ID)
		require.Error(t, err, "an independently-retired secret must not be resurrected")

		var ev models.AuditEvent
		require.NoError(t, db.Where("event_type = ? AND project_id = ?", "project.restored", p.ID).First(&ev).Error)
		assert.Contains(t, ev.Description, "1 environment", "the audit trail must itemize the restored environment count")
		assert.Contains(t, ev.Description, "1 secret", "the audit trail must itemize the restored secret count — excluding the independently-deleted one")
	})

	t.Run("environment.restored", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj2"})
		require.NoError(t, err)
		e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteEnvironment(ctx, e.ID))
		require.NoError(t, c.RestoreEnvironment(ctx, 42, p.ID, e.ID))
		require.NotNil(t, auditActor("environment.restored"))
	})
}
