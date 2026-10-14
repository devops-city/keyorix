// store_s18_test.go — white-box coverage sweep for s18 gaps.
//
// Targets (DB-error paths not previously covered):
//   - local_auth.go:230          CreatePersonalAccessToken
//   - local_auth.go:326          CreateSetupToken
//   - local_break_glass.go:62    UpdateBreakGlassActivation
//   - local_legal_hold.go:60     UpdateLegalHold
//   - local_memberships.go:56    UpdateProjectMembership
//   - local_notifications.go:133 MarkAllNotificationsRead
//   - local_rbac.go:28           CreatePermission
//   - local_rbac.go:45           CreateRole
//   - local_rbac.go:74           UpdateRole
//   - local_rbac.go:179          RemoveAllProjectRoleGrants
//   - local_risk_exceptions.go:49 UpdateRiskException
//   - local_secrets.go:402       CreateSecret
//   - local_secrets.go:454       UpdateSecret
//   - local_secrets.go:463       SetSecretCertNotAfter
//   - local_secrets.go:818       IncrementSecretReadCount
//   - local_sharing.go:26        CreateShareRecord (DB-error inner path)
//   - local_users.go:199         UpdateLastLogin
//   - local_users.go:381         UpdateGroup
//
// Pattern: open a fresh SQLite :memory: DB, seed required rows for the happy
// path (so we know the function works), then close the underlying *sql.DB to
// force the error path. newBrokenDB (store_coverage_gaps_test.go) is reused
// for functions that only need "no table" to hit the error.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS18Store opens a fresh in-memory SQLite DB, migrates the supplied models,
// and returns the LocalStorage. Use closeDB(t, ls) to force error paths.
func newS18Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// closeS18DB retrieves the *sql.DB from the LocalStorage's gorm.DB and closes
// it, causing all subsequent GORM calls to fail with a "sql: database is
// closed" error — the canonical way to exercise the error-return paths.
func closeS18DB(t *testing.T, ls *LocalStorage) {
	t.Helper()
	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

// ---------------------------------------------------------------------------
// local_auth.go:230 — CreatePersonalAccessToken
// ---------------------------------------------------------------------------

func TestCreatePersonalAccessToken_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.PersonalAccessToken{})
	// #2701: a session/PAT insert now re-reads its owning user and rolls back if
	// it is not live, so this fixture needs the owners it references to exist.
	seedCredentialOwners(t, ls.db)
	ctx := context.Background()

	tok, err := ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID:    1,
		Name:      "ci-token",
		TokenHash: "aabbcc",
	})
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.NotZero(t, tok.ID)
}

func TestCreatePersonalAccessToken_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.PersonalAccessToken{})
	closeS18DB(t, ls)

	_, err := ls.CreatePersonalAccessToken(context.Background(), &models.PersonalAccessToken{
		UserID:    1,
		Name:      "tok",
		TokenHash: "hash",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go:326 — CreateSetupToken
// ---------------------------------------------------------------------------

func TestCreateSetupToken_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.SetupToken{})
	ctx := context.Background()

	tok, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "deadbeef",
		Purpose:   "account_setup",
		State:     "active",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.NotZero(t, tok.ID)
}

func TestCreateSetupToken_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.SetupToken{})
	closeS18DB(t, ls)

	_, err := ls.CreateSetupToken(context.Background(), &models.SetupToken{
		TokenHash: "deadbeef",
		Purpose:   "account_setup",
		State:     "active",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_break_glass.go:62 — UpdateBreakGlassActivation
// ---------------------------------------------------------------------------

func TestUpdateBreakGlassActivation_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	a := &models.BreakGlassActivation{
		ProjectID:     1,
		UserID:        2,
		RoleID:        3,
		RoleName:      "emergency",
		Justification: "incident",
		State:         "active",
	}
	require.NoError(t, ls.db.Create(a).Error)

	a.State = "expired"
	err := ls.UpdateBreakGlassActivation(ctx, a)
	require.NoError(t, err)
}

func TestUpdateBreakGlassActivation_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	a := &models.BreakGlassActivation{
		ProjectID:     1,
		UserID:        2,
		RoleID:        3,
		RoleName:      "emergency",
		Justification: "incident",
		State:         "active",
	}
	require.NoError(t, ls.db.Create(a).Error)
	closeS18DB(t, ls)

	a.State = "expired"
	err := ls.UpdateBreakGlassActivation(ctx, a)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_legal_hold.go:60 — UpdateLegalHold
// ---------------------------------------------------------------------------

func TestUpdateLegalHold_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.LegalHold{})
	ctx := context.Background()

	h := &models.LegalHold{
		Reason:   "litigation hold",
		PlacedBy: 1,
		PlacedAt: time.Now(),
		Released: false,
	}
	require.NoError(t, ls.db.Create(h).Error)

	h.Released = true
	releasedAt := time.Now()
	h.ReleasedAt = &releasedAt
	err := ls.UpdateLegalHold(ctx, h)
	require.NoError(t, err)
}

func TestUpdateLegalHold_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.LegalHold{})
	ctx := context.Background()

	h := &models.LegalHold{
		Reason:   "litigation hold",
		PlacedBy: 1,
		PlacedAt: time.Now(),
		Released: false,
	}
	require.NoError(t, ls.db.Create(h).Error)
	closeS18DB(t, ls)

	h.Released = true
	err := ls.UpdateLegalHold(ctx, h)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go:133 — MarkAllNotificationsRead
// ---------------------------------------------------------------------------

func TestMarkAllNotificationsRead_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.Notification{})
	ctx := context.Background()

	pid := uint(10)
	require.NoError(t, ls.db.Create(&models.Notification{
		UserID:    5,
		ProjectID: &pid,
		Type:      "info",
		Title:     "T",
		Message:   "M",
		IsRead:    false,
	}).Error)

	err := ls.MarkAllNotificationsRead(ctx, 5)
	require.NoError(t, err)
}

func TestMarkAllNotificationsRead_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.Notification{})
	closeS18DB(t, ls)

	err := ls.MarkAllNotificationsRead(context.Background(), 5)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go:28 — CreatePermission
// ---------------------------------------------------------------------------

func TestCreatePermission_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.Permission{})
	ctx := context.Background()

	p, err := ls.CreatePermission(ctx, &models.Permission{
		Name:     "secret.read",
		Resource: "secret",
		Action:   "read",
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.NotZero(t, p.ID)
}

func TestCreatePermission_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.Permission{})
	closeS18DB(t, ls)

	_, err := ls.CreatePermission(context.Background(), &models.Permission{
		Name:     "secret.read",
		Resource: "secret",
		Action:   "read",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go:45 — CreateRole
// ---------------------------------------------------------------------------

func TestCreateRole_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.Role{})
	ctx := context.Background()

	viewerName, err := identity.NewFoldedName("viewer")
	require.NoError(t, err)
	r, err := ls.CreateRole(ctx, viewerName, "read-only")
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.NotZero(t, r.ID)
}

func TestCreateRole_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.Role{})
	closeS18DB(t, ls)

	viewerName, err := identity.NewFoldedName("viewer")
	require.NoError(t, err)
	_, err = ls.CreateRole(context.Background(), viewerName, "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go:74 — UpdateRole
// ---------------------------------------------------------------------------

func TestUpdateRole_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.Role{})
	ctx := context.Background()

	r := &models.Role{Name: "editor"}
	require.NoError(t, ls.db.Create(r).Error)

	r.Description = "can edit"
	updated, err := ls.UpdateRole(ctx, r)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "can edit", updated.Description)
}

func TestUpdateRole_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.Role{})
	ctx := context.Background()

	r := &models.Role{Name: "editor"}
	require.NoError(t, ls.db.Create(r).Error)
	closeS18DB(t, ls)

	r.Description = "can edit"
	_, err := ls.UpdateRole(ctx, r)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go:179 — RemoveAllProjectRoleGrants
// ---------------------------------------------------------------------------

func TestRemoveAllProjectRoleGrants_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.UserRole{})
	ctx := context.Background()

	// Seed a grant for user=1 at project=5.
	require.NoError(t, ls.db.Create(&models.UserRole{
		UserID: 1, RoleID: 10, ProjectID: 5, EnvironmentID: 0,
	}).Error)

	err := ls.RemoveAllProjectRoleGrants(ctx, 1, 5)
	require.NoError(t, err)

	var count int64
	require.NoError(t, ls.db.Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ?", 1, 5).Count(&count).Error)
	assert.Zero(t, count)
}

func TestRemoveAllProjectRoleGrants_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.UserRole{})
	closeS18DB(t, ls)

	err := ls.RemoveAllProjectRoleGrants(context.Background(), 1, 5)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:402 — CreateSecret
// ---------------------------------------------------------------------------

func TestCreateSecret_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.SecretNode{})
	closeS18DB(t, ls)

	_, err := ls.CreateSecret(context.Background(), &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          "db-password",
		IsSecret:      true,
		Type:          "text",
		Status:        "active",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:454 — UpdateSecret
// ---------------------------------------------------------------------------

func TestUpdateSecret_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.SecretNode{})
	ctx := context.Background()

	s := &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          "api-key",
		IsSecret:      true,
		Type:          "text",
		Status:        "active",
	}
	require.NoError(t, ls.db.Create(s).Error)

	s.Status = "inactive"
	updated, err := ls.UpdateSecret(ctx, s)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "inactive", updated.Status)
}

func TestUpdateSecret_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.SecretNode{})
	ctx := context.Background()

	s := &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          "api-key",
		IsSecret:      true,
		Type:          "text",
		Status:        "active",
	}
	require.NoError(t, ls.db.Create(s).Error)
	closeS18DB(t, ls)

	s.Status = "inactive"
	_, err := ls.UpdateSecret(ctx, s)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:463 — SetSecretCertNotAfter
// ---------------------------------------------------------------------------

func TestSetSecretCertNotAfter_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.SecretNode{})
	ctx := context.Background()

	s := &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          "tls-cert",
		IsSecret:      true,
		Type:          "certificate",
		Status:        "active",
	}
	require.NoError(t, ls.db.Create(s).Error)

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	err := ls.SetSecretCertNotAfter(ctx, s.ID, &notAfter)
	require.NoError(t, err)
}

func TestSetSecretCertNotAfter_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.SecretNode{})
	closeS18DB(t, ls)

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	err := ls.SetSecretCertNotAfter(context.Background(), 1, &notAfter)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:818 — IncrementSecretReadCount
// ---------------------------------------------------------------------------

func TestIncrementSecretReadCount_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.SecretVersion{})
	ctx := context.Background()

	v := &models.SecretVersion{
		SecretNodeID:  1,
		VersionNumber: 1,
		ReadCount:     0,
	}
	require.NoError(t, ls.db.Create(v).Error)

	err := ls.IncrementSecretReadCount(ctx, v.ID)
	require.NoError(t, err)

	var got models.SecretVersion
	require.NoError(t, ls.db.First(&got, v.ID).Error)
	assert.Equal(t, 1, got.ReadCount)
}

func TestIncrementSecretReadCount_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.SecretVersion{})
	closeS18DB(t, ls)

	err := ls.IncrementSecretReadCount(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sharing.go:26 — CreateShareRecord (DB-error inner path)
//
// CreateShareRecord performs validation + secret lookup + user/group lookup
// before hitting the DB. The only way to exercise the pure DB-error path at
// line 78 (ls.db.Create(share).Error) while passing all the pre-checks is to
// seed the required rows (secret + user) and then close the DB.
// ---------------------------------------------------------------------------

func TestCreateShareRecord_BrokenDB(t *testing.T) {
	// Need User, SecretNode, Group, ShareRecord tables for CreateShareRecord.
	ls := newS18Store(t,
		&models.User{},
		&models.Group{},
		&models.SecretNode{},
		&models.ShareRecord{},
	)
	ctx := context.Background()

	// Seed owner and recipient users.
	owner := &models.User{Username: "owner", Email: "owner@test.io"}
	require.NoError(t, ls.db.Create(owner).Error)
	recipient := &models.User{Username: "bob", Email: "bob@test.io"}
	require.NoError(t, ls.db.Create(recipient).Error)

	// Seed the secret owned by the owner.
	secret := &models.SecretNode{
		ProjectID:     1,
		EnvironmentID: 1,
		Name:          "shared-secret",
		IsSecret:      true,
		Type:          "text",
		Status:        "active",
		OwnerID:       owner.ID,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	// Close the DB to trigger the error on the Create path.
	closeS18DB(t, ls)

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_users.go:199 — UpdateLastLogin
// ---------------------------------------------------------------------------

func TestUpdateLastLogin_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.User{})
	ctx := context.Background()

	u := &models.User{Username: "alice", Email: "alice@test.io"}
	require.NoError(t, ls.db.Create(u).Error)

	err := ls.UpdateLastLogin(ctx, u.ID, time.Now())
	require.NoError(t, err)
}

func TestUpdateLastLogin_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.User{})
	closeS18DB(t, ls)

	err := ls.UpdateLastLogin(context.Background(), 1, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_users.go:381 — UpdateGroup
// ---------------------------------------------------------------------------

func TestUpdateGroup_HappyPath(t *testing.T) {
	ls := newS18Store(t, &models.Group{})
	ctx := context.Background()

	g := &models.Group{Name: "engineers", Description: "engineering team"}
	require.NoError(t, ls.db.Create(g).Error)

	desc := "all engineers"
	matched, err := ls.UpdateGroupFields(ctx, g.ID, nil, nil, &desc, time.Now())
	require.NoError(t, err)
	require.True(t, matched)
	updated, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "all engineers", updated.Description)
}

func TestUpdateGroup_BrokenDB(t *testing.T) {
	ls := newS18Store(t, &models.Group{})
	ctx := context.Background()

	g := &models.Group{Name: "engineers", Description: "engineering team"}
	require.NoError(t, ls.db.Create(g).Error)
	closeS18DB(t, ls)

	desc := "all engineers"
	_, err := ls.UpdateGroupFields(ctx, g.ID, nil, nil, &desc, time.Now())
	require.Error(t, err)
}
