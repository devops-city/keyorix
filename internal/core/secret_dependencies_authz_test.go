// secret_dependencies_authz_test.go — #G32 regression tests: secret-relationship
// functions (secret_dependencies.go, blast_radius.go, secret_impact_preview.go) used
// to authorize only the FOCAL (path) secret and disclose/act on a PEER secret with no
// independent check, reasoning that "same project+environment" was equivalent to "the
// caller is authorized." It is not: this codebase's authorization model includes
// per-secret ACL grants (GrantSecretACL / AuthorizeSecretPrincipal → HasSecretACL) that
// do NOT extend to a peer secret merely because it shares the focal secret's project and
// environment. These tests reproduce the group's own detection_idea: grant a caller an
// ACL on the focal secret only (no project-wide role, so it has no ambient visibility
// into any other secret), link a peer the caller has no grant on, and assert the peer's
// name/ID never leaks — and that a mutation touching the peer is rejected.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// authzTestActor is the low-privilege caller used throughout this file: an ACL grant
// on specific secrets only, no project-wide role — so it has no ambient authorization
// on any secret it wasn't explicitly granted.
const authzTestActor = uint(50)

// newDepAuthzCore builds an isolated in-memory core with the RBAC/ACL tables migrated.
func newDepAuthzCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretDependency{}, &models.SecretACL{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.MachineIdentityRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	// Placeholder project membership: GrantSecretACL requires the grantee to already be
	// a project member (mirrors secret_acl_test.go's newACLCore). RoleID 999 is a
	// placeholder — membership is checked on user_id+project_id, not the role itself.
	require.NoError(t, db.Create(&models.UserRole{UserID: authzTestActor, RoleID: 999, ProjectID: 1}).Error)
	// The granting actor (0) needs no setup: writeAuditEvent tolerates actor 0, and
	// GrantSecretACL below is called directly by the test as a fixture step, not through
	// an authorization path of its own.
	now := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkAuthzSecret inserts a secret into project 1 / environment 1.
func mkAuthzSecret(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

// grantDepACL gives authzTestActor secrets.read+secrets.write on secretID, via a
// per-secret ACL grant — NOT a project/environment role, so it confers no visibility
// into any other secret.
func grantDepACL(t *testing.T, c *KeyorixCore, secretID uint) {
	t.Helper()
	require.NoError(t, c.GrantSecretACL(context.Background(), 1, secretID, authzTestActor, []string{"secrets.read", "secrets.write"}))
}

// TestListSecretDependencies_DoesNotDiscloseUnauthorizedPeer is the read-path
// regression: authzTestActor has an ACL grant on the focal secret and on one of its two
// peers, but not the other. Same project+environment membership must not stand in for
// authorization on the unauthorized peer.
func TestListSecretDependencies_DoesNotDiscloseUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	seen := mkAuthzSecret(t, db, "peer-authorized")
	hidden := mkAuthzSecret(t, db, "peer-hidden")
	grantDepACL(t, c, focal)
	grantDepACL(t, c, seen)
	// No grant on `hidden` at all.

	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: focal, DependsOnSecretID: seen}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: focal, DependsOnSecretID: hidden}).Error)

	deps, err := c.ListSecretDependencies(context.Background(), ActorTypeUser, authzTestActor, focal)
	require.NoError(t, err)
	ids := make([]uint, 0, len(deps.DependsOn))
	for _, e := range deps.DependsOn {
		ids = append(ids, e.SecretID)
	}
	assert.Contains(t, ids, seen, "an authorized peer must still be disclosed")
	assert.NotContains(t, ids, hidden, "a peer the caller has no independent grant on must never be disclosed")
}

// TestGetSecretImpact_DoesNotDiscloseUnauthorizedPeer covers the transitive-impact view:
// the BFS must still traverse through an unauthorized peer to find further,
// independently-authorized dependents, but must never disclose the unauthorized peer
// itself.
func TestGetSecretImpact_DoesNotDiscloseUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	hidden := mkAuthzSecret(t, db, "hidden-mid")
	beyond := mkAuthzSecret(t, db, "beyond-hidden")
	grantDepACL(t, c, focal)
	grantDepACL(t, c, beyond) // authorized on the far node, NOT on the hidden hop between them
	// hidden depends on focal (depth 1); beyond depends on hidden (depth 2).
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: hidden, DependsOnSecretID: focal}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: beyond, DependsOnSecretID: hidden}).Error)

	impact, err := c.GetSecretImpact(context.Background(), ActorTypeUser, authzTestActor, focal)
	require.NoError(t, err)
	ids := make([]uint, 0, len(impact.Affected))
	for _, a := range impact.Affected {
		ids = append(ids, a.SecretID)
	}
	assert.NotContains(t, ids, hidden, "the unauthorized hop must not be disclosed")
	assert.Contains(t, ids, beyond, "a hop through an unauthorized peer must still surface a further, independently-authorized dependent")
}

// TestGetBlastRadius_DoesNotDiscloseUnauthorizedPeer mirrors the GetSecretImpact
// regression for the richer blast-radius report.
func TestGetBlastRadius_DoesNotDiscloseUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	hidden := mkAuthzSecret(t, db, "hidden-mid")
	beyond := mkAuthzSecret(t, db, "beyond-hidden")
	grantDepACL(t, c, focal)
	grantDepACL(t, c, beyond)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: hidden, DependsOnSecretID: focal}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: beyond, DependsOnSecretID: hidden}).Error)

	report, err := c.GetBlastRadius(context.Background(), ActorTypeUser, authzTestActor, focal)
	require.NoError(t, err)
	ids := make([]uint, 0, len(report.Dependents))
	for _, n := range report.Dependents {
		ids = append(ids, n.SecretID)
	}
	assert.NotContains(t, ids, hidden, "the unauthorized hop must not be disclosed")
	assert.Contains(t, ids, beyond, "a hop through an unauthorized peer must still surface a further, independently-authorized dependent")
}

// TestGetSecretImpactPreview_CountsFullButIDsFiltered: the cascade-delete preview's
// counts reflect the TRUE full impact (an operator needs the real size to decide
// whether to delete), but the identifying AffectedSecretIDs list is filtered to only
// the peers the caller is independently authorized to read.
func TestGetSecretImpactPreview_CountsFullButIDsFiltered(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	seen := mkAuthzSecret(t, db, "peer-authorized")
	hidden := mkAuthzSecret(t, db, "peer-hidden")
	grantDepACL(t, c, focal)
	grantDepACL(t, c, seen)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: seen, DependsOnSecretID: focal}).Error)
	require.NoError(t, db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: hidden, DependsOnSecretID: focal}).Error)

	preview, err := c.GetSecretImpactPreview(context.Background(), ActorTypeUser, authzTestActor, focal)
	require.NoError(t, err)
	assert.Equal(t, 2, preview.DirectDependents, "the true cascade count is disclosed even though one peer's identity is not")
	assert.Equal(t, 2, preview.TransitiveDependents)
	assert.Contains(t, preview.AffectedSecretIDs, seen)
	assert.NotContains(t, preview.AffectedSecretIDs, hidden, "an unauthorized peer's ID must not appear in the identifying list")
}

// TestAddSecretDependency_RejectsUnauthorizedPeer is the write-path regression: the
// caller is authorized (secrets.write) on the focal secret but has no grant at all on
// the dependency target — same project+environment must not substitute for an
// independent authorization check on the target.
func TestAddSecretDependency_RejectsUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	target := mkAuthzSecret(t, db, "unauthorized-target")
	grantDepACL(t, c, focal)
	// No grant on `target`.

	_, err := c.AddSecretDependency(context.Background(), ActorTypeUser, authzTestActor, focal, target, "", 0)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unauthorized-target", "must not leak the target's name in the error")

	var count int64
	require.NoError(t, db.Model(&models.SecretDependency{}).Count(&count).Error)
	assert.Zero(t, count, "no edge must be persisted when the target is unauthorized")
}

// TestRemoveSecretDependency_RejectsUnauthorizedPeer: the caller is authorized on the
// focal (path) secret but not on the edge's other endpoint — removal must be rejected,
// not silently allowed because both endpoints share a project+environment.
func TestRemoveSecretDependency_RejectsUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	c, db := newDepAuthzCore(t)
	focal := mkAuthzSecret(t, db, "focal")
	target := mkAuthzSecret(t, db, "unauthorized-target")
	grantDepACL(t, c, focal)
	// No grant on `target`.
	edge := &models.SecretDependency{ProjectID: 1, DependentSecretID: focal, DependsOnSecretID: target}
	require.NoError(t, db.Create(edge).Error)

	err := c.RemoveSecretDependency(context.Background(), ActorTypeUser, authzTestActor, focal, edge.ID)
	require.Error(t, err)

	var count int64
	require.NoError(t, db.Model(&models.SecretDependency{}).Where("id = ?", edge.ID).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the edge must not be removed when the caller lacks authorization on the peer")
}
