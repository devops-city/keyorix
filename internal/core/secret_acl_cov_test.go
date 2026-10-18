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

// --- storage stubs for error-path coverage ---

type ancestorErrStorage struct {
	corestorage.Storage
	err error
}

func (s *ancestorErrStorage) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	return nil, s.err
}

type getACLErrStorage struct {
	corestorage.Storage
	err error
}

func (s *getACLErrStorage) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	return nil, s.err
}

type createACLErrStorage struct {
	corestorage.Storage
	err error
}

func (s *createACLErrStorage) CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error {
	return s.err
}

// WithTransaction keeps the fault on the transaction-scoped handle: the grant
// is written through tx since AUDIT-TX-2 (it commits with its audit row).
func (s *createACLErrStorage) WithTransaction(ctx context.Context, fn func(corestorage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx corestorage.Storage) error {
		return fn(&createACLErrStorage{Storage: tx, err: s.err})
	})
}

type listACLErrStorage struct {
	corestorage.Storage
	err error
}

func (s *listACLErrStorage) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	return nil, s.err
}

type deleteACLErrStorage struct {
	corestorage.Storage
	acls []*models.SecretACL
	err  error
}

// WithTransaction re-wraps the transaction handle so the injected failure still fires
// now that the write runs inside the mutation's audited transaction (AUDIT-TX-3).
func (s *deleteACLErrStorage) WithTransaction(ctx context.Context, fn func(corestorage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx corestorage.Storage) error {
		wrapped := *s
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (s *deleteACLErrStorage) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	return s.acls, nil
}

func (s *deleteACLErrStorage) DeleteSecretACL(ctx context.Context, id uint) error {
	return s.err
}

// ancestorLoopErrStorage returns the direct secretID with a not-found error
// (so the direct ACL check passes through) then returns real ancestors so the
// loop can be entered, and finally returns a non-not-found error from GetSecretACL
// for any ancestorID, triggering the loop-error path (line 180–182).
type ancestorLoopErrStorage struct {
	corestorage.Storage
	directID uint
	loopErr  error
}

func (s *ancestorLoopErrStorage) GetSecretAncestors(_ context.Context, _ uint) ([]uint, error) {
	return []uint{9999}, nil
}

func (s *ancestorLoopErrStorage) GetSecretACL(_ context.Context, secretID, _ uint) (*models.SecretACL, error) {
	if secretID == s.directID {
		return nil, errors.New("record not found")
	}
	return nil, s.loopErr
}

// newACLCoreWithStorage builds a KeyorixCore using the given storage backend,
// inheriting the clock from base.
func newACLCoreWithStorage(base *KeyorixCore, st corestorage.Storage) *KeyorixCore {
	return &KeyorixCore{storage: st, now: base.now}
}

// --- EncodeSecretACLPerms ---

func TestEncodeSecretACLPerms_Empty(t *testing.T) {
	t.Parallel()
	_, err := EncodeSecretACLPerms([]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one permission is required")
}

func TestEncodeSecretACLPerms_Nil(t *testing.T) {
	t.Parallel()
	_, err := EncodeSecretACLPerms(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one permission is required")
}

// --- DecodeSecretACLPerms ---

func TestDecodeSecretACLPerms_EmptyString(t *testing.T) {
	t.Parallel()
	assert.Nil(t, DecodeSecretACLPerms(""))
}

func TestDecodeSecretACLPerms_BadJSON(t *testing.T) {
	t.Parallel()
	assert.Nil(t, DecodeSecretACLPerms("not-valid-json"))
}

// --- GrantSecretACL validation errors ---

func TestGrantSecretACL_ZeroActorID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "g-actor-zero")
	err := c.GrantSecretACL(ctx, 0, sid, 1, []string{"secrets.read"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor ID is required")
}

func TestGrantSecretACL_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newACLCore(t)
	err := c.GrantSecretACL(ctx, 1, 0, 1, []string{"secrets.read"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGrantSecretACL_ZeroUserID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "g-user-zero")
	err := c.GrantSecretACL(ctx, 1, sid, 0, []string{"secrets.read"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestGrantSecretACL_EmptyPermsSlice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "g-empty-perms")
	err := c.GrantSecretACL(ctx, 1, sid, 1, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one permission is required")
}

func TestGrantSecretACL_MissingSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newACLCore(t)
	// secretID 99999 does not exist → requireSecret returns error.
	err := c.GrantSecretACL(ctx, 1, 99999, 1, []string{"secrets.read"})
	require.Error(t, err)
}

func TestGrantSecretACL_CreateOrUpdateError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "g-create-err")
	wantErr := errors.New("write failed")
	c2 := newACLCoreWithStorage(c, &createACLErrStorage{Storage: c.storage, err: wantErr})
	err := c2.GrantSecretACL(ctx, 1, sid, 1, []string{"secrets.read"})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- RevokeSecretACL ---

func TestRevokeSecretACL_ZeroACLID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "rv-zero-id")
	err := c.RevokeSecretACL(ctx, 1, sid, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACL ID is required")
}

func TestRevokeSecretACL_ListError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "rv-list-err")
	wantErr := errors.New("list failed")
	c2 := newACLCoreWithStorage(c, &listACLErrStorage{Storage: c.storage, err: wantErr})
	err := c2.RevokeSecretACL(ctx, 1, sid, 99)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestRevokeSecretACL_DeleteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "rv-delete-err")
	wantErr := errors.New("delete failed")
	fakeACL := &models.SecretACL{ID: 77, SecretID: sid, UserID: 5}
	stub := &deleteACLErrStorage{Storage: c.storage, acls: []*models.SecretACL{fakeACL}, err: wantErr}
	c2 := newACLCoreWithStorage(c, stub)
	err := c2.RevokeSecretACL(ctx, 1, sid, 77)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- HasSecretACL ancestor paths ---

func TestHasSecretACL_AncestorStorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "ha-anc-err")
	wantErr := errors.New("ancestors unavailable")
	c2 := newACLCoreWithStorage(c, &ancestorErrStorage{Storage: c.storage, err: wantErr})
	_, err := c2.HasSecretACL(ctx, 99, sid, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestHasSecretACL_AncestorLoopACLError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "ha-loop-err")
	wantErr := errors.New("acl lookup failed in ancestor loop")
	stub := &ancestorLoopErrStorage{Storage: c.storage, directID: sid, loopErr: wantErr}
	c2 := newACLCoreWithStorage(c, stub)
	_, err := c2.HasSecretACL(ctx, 99, sid, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- aclGrantsPermission non-not-found error ---

func TestAclGrantsPermission_NonNotFoundErr(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "ggp-non-notfound")
	wantErr := errors.New("unexpected db failure")
	c2 := newACLCoreWithStorage(c, &getACLErrStorage{Storage: c.storage, err: wantErr})
	got, err := c2.aclGrantsPermission(ctx, sid, 99, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, got)
}

// --- AuthorizeSecret error propagation from HasSecretACL ---

// TestAuthorizeSecret_HasSecretACLError verifies AuthorizeSecret fails closed
// ((false, err)) when the underlying SecretACL lookup errors -- even for a user
// who ALSO holds a project role that would otherwise grant access via the RBAC
// fallback (c.Authorize). Without the `if err != nil { return false, err }` guard
// immediately after HasSecretACL (authz.go's AuthorizeSecret), execution would
// fall through past the error with hasACL's zero value (false), skip the "hasACL"
// branch, and reach the RBAC fallback anyway -- silently discarding the ACL
// resolution error and returning (true, nil) purely because the user's project
// role happens to also grant the permission. The project-role setup here is
// deliberate, not incidental: a user with NO project role would (coincidentally)
// still be denied even with the guard missing, masking the bug entirely; only a
// user who WOULD be granted via the fallback exposes the difference a mutant
// deleting this guard needs a test to catch.
func TestAuthorizeSecret_HasSecretACLError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "acl-err-with-role")

	// User 400 holds a real project role granting secrets.read.
	role := &models.Role{Name: "project_admin_400", Description: "admin"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 400, RoleID: role.ID, ProjectID: 1}).Error)

	// Sanity check: without any injected error, this user IS granted access via
	// the RBAC fallback -- confirms the project-role setup actually works, so the
	// assertion below is testing error propagation, not an unrelated setup bug.
	okBaseline, errBaseline := c.AuthorizeSecret(ctx, 400, sid, "secrets.read")
	require.NoError(t, errBaseline)
	require.True(t, okBaseline, "test setup: user 400's project role must grant access on its own")

	// Now inject a SecretACL lookup failure and confirm it is NOT silently
	// swallowed by the RBAC fallback.
	wantErr := errors.New("secret acl lookup unavailable")
	c2 := newACLCoreWithStorage(c, &getACLErrStorage{Storage: c.storage, err: wantErr})
	ok, err := c2.AuthorizeSecret(ctx, 400, sid, "secrets.read")
	require.Error(t, err, "AuthorizeSecret must fail closed when HasSecretACL errors, even though the user's project role would otherwise grant access")
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, ok)
}

// --- isNotFound ---

func TestIsNotFound_Nil(t *testing.T) {
	t.Parallel()
	assert.False(t, isNotFound(nil))
}

func TestIsNotFound_Messages(t *testing.T) {
	t.Parallel()
	assert.True(t, isNotFound(errors.New("record not found")))
	assert.True(t, isNotFound(errors.New("entry not found")))
	assert.False(t, isNotFound(errors.New("some other error")))
}
