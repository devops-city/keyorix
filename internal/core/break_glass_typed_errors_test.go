package core

// #2905: ActivateBreakGlass / RevokeBreakGlass refusals are classified by
// sentinel (errors.Is), and the user-visible text is exactly what it was before
// the sentinels existed. The English messages are pinned verbatim so a refactor
// that "tidies" them into a fmt.Errorf("%w") chain (which appends the
// sentinel's own text) fails here.

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

func TestActivateBreakGlass_RefusalsAreSentinelsWithUnchangedText(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-typed-errors"})
	require.NoError(t, err)
	member, err := st.CreateUser(ctx, foldedTestUser(t, "bg-typed-member", "bg-typed-member@example.com"))
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, member.ID, viewer.ID, storage.Scope{ProjectID: proj.ID}))
	outsider, err := st.CreateUser(ctx, foldedTestUser(t, "bg-typed-outsider", "bg-typed-outsider@example.com"))
	require.NoError(t, err)

	const just = "prod incident, database is down"

	// Disabled (the default policy).
	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, just, "")
	require.ErrorIs(t, err, ErrBreakGlassDisabled)
	// #2943: the disabled refusal says it is disabled and which key enables it
	// (the "permission denied" prefix is kept for the 403 mapping).
	assert.EqualError(t, err, "permission denied: "+errBreakGlassDisabled)

	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "editor", DefaultTTL: time.Hour, MaxTTL: time.Hour})

	_, err = c.ActivateBreakGlass(ctx, 0, member.ID, just, "")
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.EqualError(t, err, "Validation error: project ID and user are required")

	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, "short", "")
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.EqualError(t, err, "Validation error: a justification of at least 10 characters is required for emergency access")

	_, err = c.ActivateBreakGlass(ctx, proj.ID, outsider.ID, just, "")
	require.ErrorIs(t, err, ErrBreakGlassNotProjectMember)
	assert.EqualError(t, err, "permission denied: break-glass is available only to members of the project")

	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, just, "soon")
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.EqualError(t, err, "Validation error: ttl must be a positive Go duration (e.g. 2h)")

	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "", DefaultTTL: time.Hour, MaxTTL: time.Hour})
	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, just, "")
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.EqualError(t, err, "Validation error: no emergency role is configured")

	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "no-such-role", DefaultTTL: time.Hour, MaxTTL: time.Hour})
	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, just, "")
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.Contains(t, err.Error(), `emergency role "no-such-role" not found: `)
}

func TestRevokeBreakGlass_RefusalsAreSentinelsWithUnchangedText(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-typed-revoke"})
	require.NoError(t, err)
	member, err := st.CreateUser(ctx, foldedTestUser(t, "bg-typed-revoker", "bg-typed-revoker@example.com"))
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, member.ID, viewer.ID, storage.Scope{ProjectID: proj.ID}))
	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "editor", DefaultTTL: time.Hour, MaxTTL: time.Hour})
	act, err := c.ActivateBreakGlass(ctx, proj.ID, member.ID, "prod incident, database is down", "")
	require.NoError(t, err)

	err = c.RevokeBreakGlass(ctx, member.ID, 0, 0, act.ID)
	require.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.EqualError(t, err, "Validation error: project ID is required")

	err = c.RevokeBreakGlass(ctx, member.ID, 0, proj.ID, 999999)
	require.ErrorIs(t, err, storage.ErrBreakGlassNotFound)
	assert.Contains(t, err.Error(), "Resource not found: ")

	err = c.RevokeBreakGlass(ctx, member.ID, 0, proj.ID+1, act.ID)
	require.ErrorIs(t, err, storage.ErrBreakGlassNotFound)
	assert.EqualError(t, err, "Resource not found")

	require.NoError(t, c.RevokeBreakGlass(ctx, member.ID, 0, proj.ID, act.ID))
	err = c.RevokeBreakGlass(ctx, member.ID, 0, proj.ID, act.ID)
	require.ErrorIs(t, err, storage.ErrBreakGlassNotActive)
	assert.EqualError(t, err, "Validation error: activation is not active")
	assert.False(t, errors.Is(err, storage.ErrBreakGlassNotFound), "sentinels must not bleed into each other")
}

// getRoleByNameErrStub overrides exactly GetRoleByName to inject a fixed error.
func getRoleByNameErrStub(inner storage.Storage, err error) storage.Storage {
	return hooked(inner, &storeHooks{
		GetRoleByName: func(_ storage.Storage, ctx context.Context, name string) (*models.Role, error) {
			return nil, err
		},
	})
}

// A storage failure while resolving the emergency role is an internal error:
// it must NOT carry ErrBreakGlassInvalidRequest (which the HTTP handler maps to
// 400 and echoes verbatim), and its text must not name the emergency role.
func TestActivateBreakGlass_RoleLookupDBFailureIsInternalNotInvalidRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-typed-brokendb"})
	require.NoError(t, err)
	member, err := st.CreateUser(ctx, foldedTestUser(t, "bg-brokendb-member", "bg-brokendb-member@example.com"))
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, member.ID, viewer.ID, storage.Scope{ProjectID: proj.ID}))
	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "editor", DefaultTTL: time.Hour, MaxTTL: time.Hour})

	dbErr := errors.New("pq: connection refused (driver detail)")
	c.storage = getRoleByNameErrStub(c.storage, dbErr)

	_, err = c.ActivateBreakGlass(ctx, proj.ID, member.ID, "prod incident, database is down", "")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrBreakGlassInvalidRequest), "a DB failure must not be classed as a client error")
	assert.NotContains(t, err.Error(), "editor", "the emergency role name must not appear in the error")
	assert.ErrorIs(t, err, dbErr, "the underlying error stays reachable for logging")
}
