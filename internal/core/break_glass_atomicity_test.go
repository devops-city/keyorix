package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failBreakGlassGrantStorage fails AssignRoleWithExpiry while armed, on the
// handle ActivateBreakGlass actually uses: WithTransaction re-wraps the
// transaction-scoped handle so the fault fires inside the transaction too
// (an embedded Storage would hand the callback the bare, un-faulted handle).
type failBreakGlassGrantStorage struct {
	storage.Storage
	armed *bool
}

func (s *failBreakGlassGrantStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	if *s.armed {
		return errors.New("injected fault: AssignRoleWithExpiry")
	}
	return s.Storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt)
}

func (s *failBreakGlassGrantStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&failBreakGlassGrantStorage{Storage: tx, armed: s.armed})
	})
}

// TestActivateBreakGlass_FailedGrantLeavesNoActivationRecord is the red-proof
// for #3109: the activation record and the role grant are one transaction, so
// when the grant fails NOTHING of the activation survives -- no row (neither
// 'active' nor a compensated 'revoked'), no grant audit, and the user's retry is
// not blocked by the one-active-slot unique index. Before the fix the record was
// committed first and "undone" by a second write, which left a revoked row
// behind the error (and an 'active' row with no role in between).
func TestActivateBreakGlass_FailedGrantLeavesNoActivationRecord(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-proj", Description: "d"})
	require.NoError(t, err)
	u, err := st.CreateUser(ctx, foldedTestUser(t, "responder", "responder@example.com"))
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, 1, proj.ID, u.ID, "project_viewer", false))

	c.SetBreakGlassPolicy(BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})

	armed := true
	c.storage = &failBreakGlassGrantStorage{Storage: st, armed: &armed}

	_, err = c.ActivateBreakGlass(ctx, proj.ID, u.ID, "prod incident, needs immediate access", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to grant emergency role")

	rows, err := st.ListBreakGlassActivations(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, rows, "a failed grant must leave no activation record behind (not active, not revoked)")

	events, _, eerr := st.GetAuditLogs(ctx, &storage.AuditFilter{})
	require.NoError(t, eerr)
	for _, e := range events {
		assert.NotEqual(t, EventBreakGlassActivated, e.EventType, "a failed activation must not be audited as activated")
	}

	// The slot is free: the same user can activate once the fault clears.
	armed = false
	act, err := c.ActivateBreakGlass(ctx, proj.ID, u.ID, "prod incident, needs immediate access", "")
	require.NoError(t, err)
	require.NotNil(t, act)
	assert.Equal(t, BreakGlassActive, act.State)
}
