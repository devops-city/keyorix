// rotation_policies_cov_test.go — coverage top-up for rotation_policies.go error paths.
//
// Covers:
//   - CreateRotationPolicy: scope=project with nil ProjectID; validateDescription error; storage error
//   - GetRotationPolicy: storage not-found error
//   - UpdateRotationPolicy: alert >= interval; validateDescription error; Get not-found; Update storage error
//   - DeleteRotationPolicy: Get not-found; Delete storage error
//   - EvaluateRotationPolicies: ListRotationPolicies error; inactive policy skip
package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- storage stubs for rotation policy error paths ---

type createRotPolicyErrStorage struct {
	corestorage.Storage
	err error
}

// WithTransaction re-wraps the transaction handle so the injected failure still fires
// now that the write runs inside the mutation's audited transaction (AUDIT-TX-3).
func (s *createRotPolicyErrStorage) WithTransaction(ctx context.Context, fn func(corestorage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx corestorage.Storage) error {
		wrapped := *s
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (s *createRotPolicyErrStorage) CreateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return s.err
}

type updateRotPolicyErrStorage struct {
	corestorage.Storage
	err error
}

// WithTransaction re-wraps the transaction handle so the injected failure still fires
// now that the write runs inside the mutation's audited transaction (AUDIT-TX-3).
func (s *updateRotPolicyErrStorage) WithTransaction(ctx context.Context, fn func(corestorage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx corestorage.Storage) error {
		wrapped := *s
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (s *updateRotPolicyErrStorage) UpdateRotationPolicyFields(_ context.Context, _ uint, _ corestorage.RotationPolicyFieldUpdate, _ time.Time) (bool, error) {
	return false, s.err
}

type deleteRotPolicyErrStorage struct {
	corestorage.Storage
	err error
}

// WithTransaction re-wraps the transaction handle so the injected failure still fires
// now that the write runs inside the mutation's audited transaction (AUDIT-TX-3).
func (s *deleteRotPolicyErrStorage) WithTransaction(ctx context.Context, fn func(corestorage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx corestorage.Storage) error {
		wrapped := *s
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (s *deleteRotPolicyErrStorage) DeleteRotationPolicy(_ context.Context, _ uint) error {
	return s.err
}

type listRotPoliciesErrStorage struct {
	corestorage.Storage
	err error
}

func (s *listRotPoliciesErrStorage) ListRotationPolicies(_ context.Context, _, _ *uint) ([]*models.RotationPolicy, error) {
	return nil, s.err
}

// newRotPolicyCore returns a KeyorixCore backed by an in-memory SQLite with
// the RotationPolicy + AuditEvent tables migrated.
func newRotPolicyCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}, &models.AuditEvent{}))
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// --- CreateRotationPolicy ---

func TestCreateRotationPolicy_ProjectScopeNilID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	_, err := c.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name: "p", Scope: "project", ProjectID: nil,
		IntervalDays: 90, AlertDaysBefore: 7,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id is required")
}

func TestCreateRotationPolicy_ValidateDescriptionError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	pid := uint(1)
	_, err := c.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name:         "p",
		Scope:        "project",
		ProjectID:    &pid,
		IntervalDays: 90, AlertDaysBefore: 7,
		Description: strings.Repeat("x", maxSecretDescriptionLen+1),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "description exceeds")
}

func TestCreateRotationPolicy_StorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	wantErr := errors.New("db write failed")
	c2 := &KeyorixCore{storage: &createRotPolicyErrStorage{Storage: c.storage, err: wantErr}, now: c.now}
	pid := uint(1)
	_, err := c2.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name: "p", Scope: "project", ProjectID: &pid,
		IntervalDays: 90, AlertDaysBefore: 7,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- GetRotationPolicy ---

func TestGetRotationPolicy_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	_, err := c.GetRotationPolicy(ctx, 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rotation policy")
}

// --- UpdateRotationPolicy ---

func TestUpdateRotationPolicy_AlertGTInterval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	_, err := c.UpdateRotationPolicy(ctx, 1, &UpdateRotationPolicyRequest{
		ID: 1, Name: "p", IntervalDays: 10, AlertDaysBefore: 10, IsActive: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alert_days_before must be less than interval_days")
}

func TestUpdateRotationPolicy_ValidateDescriptionError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	_, err := c.UpdateRotationPolicy(ctx, 1, &UpdateRotationPolicyRequest{
		ID: 1, Name: "p", IntervalDays: 90, AlertDaysBefore: 7, IsActive: true,
		Description: strings.Repeat("z", maxSecretDescriptionLen+1),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "description exceeds")
}

func TestUpdateRotationPolicy_GetNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	_, err := c.UpdateRotationPolicy(ctx, 1, &UpdateRotationPolicyRequest{
		ID: 99999, Name: "p", IntervalDays: 90, AlertDaysBefore: 7, IsActive: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rotation policy")
}

func TestUpdateRotationPolicy_StorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newRotPolicyCore(t)
	pid := uint(1)
	p, err := c.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name: "to-update", Scope: "project", ProjectID: &pid,
		IntervalDays: 90, AlertDaysBefore: 7,
	})
	require.NoError(t, err)
	wantErr := errors.New("update failed")
	c2 := &KeyorixCore{storage: &updateRotPolicyErrStorage{Storage: store.NewLocalStorage(db), err: wantErr}, now: c.now}
	_, err = c2.UpdateRotationPolicy(ctx, 1, &UpdateRotationPolicyRequest{
		ID: p.ID, Name: "updated", IntervalDays: 60, AlertDaysBefore: 5, IsActive: true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- DeleteRotationPolicy ---

func TestDeleteRotationPolicy_GetNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	err := c.DeleteRotationPolicy(ctx, 1, 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rotation policy")
}

func TestDeleteRotationPolicy_StorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newRotPolicyCore(t)
	pid := uint(1)
	p, err := c.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name: "to-delete", Scope: "project", ProjectID: &pid,
		IntervalDays: 90, AlertDaysBefore: 7,
	})
	require.NoError(t, err)
	wantErr := errors.New("delete failed")
	c2 := &KeyorixCore{storage: &deleteRotPolicyErrStorage{Storage: store.NewLocalStorage(db), err: wantErr}, now: c.now}
	err = c2.DeleteRotationPolicy(ctx, 1, p.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// --- EvaluateRotationPolicies ---

func TestEvaluateRotationPolicies_ListError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newRotPolicyCore(t)
	wantErr := errors.New("list failed")
	c2 := &KeyorixCore{storage: &listRotPoliciesErrStorage{Storage: c.storage, err: wantErr}, now: c.now}
	_, err := c2.EvaluateRotationPolicies(ctx, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestEvaluateRotationPolicies_InactivePolicySkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newRotPolicyCore(t)
	// Create an inactive policy — EvaluateRotationPolicies must skip it.
	pid := uint(1)
	p, err := c.CreateRotationPolicy(ctx, 1, &CreateRotationPolicyRequest{
		Name: "inactive-policy", Scope: "project", ProjectID: &pid,
		IntervalDays: 90, AlertDaysBefore: 7,
	})
	require.NoError(t, err)
	require.NoError(t, db.Model(p).Update("is_active", false).Error)

	evals, err := c.EvaluateRotationPolicies(ctx, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, evals, "inactive policy should be skipped and produce no evaluations")
}
