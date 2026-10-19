package core_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// X1: DeleteProject's post-commit dynamic-secrets cascade
// (revokeProjectDynamicSecretLeases) is documented as best-effort — an error there
// is already audited and swallowed — but a PANIC used to escape uncaught, so a
// caller whose delete had already committed still got a 500/Internal error for a
// project that was, in fact, already gone (Session L, L5 bonus fault-fuzz finding:
// `op=REST DELETE /api/v1/projects/{id} fault=ListDynamicSecretConfigs#1/panic:
// ORACLE (a) VIOLATION`). These reproduce both panic sites red-on-main (a deferred
// recover added to revokeProjectDynamicSecretLeases turns them green) and confirm
// the recover is scoped narrowly: a panic from the PRE-commit guard/cascade
// primitive itself must still propagate uncaught, not be swallowed.

// cascadePanicSpy backs both panic sites: ListDynamicSecretConfigs (X1's first
// reported panic) and, via RevokeLeasesForConfig's own ListDynamicSecretLeases
// call, the second. Embeds storage.Storage as nil like deleteProjectSpy in
// catalog_delete_project_test.go — any method besides the ones below panics on a
// nil pointer dereference if reached, so an unexpected call fails loudly.
type cascadePanicSpy struct {
	storage.Storage
	panicOnListConfigs bool
	panicOnListLeases  bool
	panicOnGuard       bool
	configs            []*models.DynamicSecretConfig
	auditEvents        []*models.AuditEvent
}

func (s *cascadePanicSpy) DeleteProjectIfEmpty(_ context.Context, id uint) (int, error) {
	if s.panicOnGuard {
		panic("simulated pre-commit guard panic")
	}
	return 0, nil
}

// WithTransaction / SuspendMachineIdentitiesForDeletedProject: DeleteProject runs the
// cascade and its machine-identity step (#3433) in one transaction; this spy has none.
func (s *cascadePanicSpy) WithTransaction(_ context.Context, fn func(storage.Storage) error) error {
	return fn(s)
}

func (s *cascadePanicSpy) SuspendMachineIdentitiesForDeletedProject(_ context.Context, _ uint) ([]*models.MachineIdentity, error) {
	return nil, nil
}

func (s *cascadePanicSpy) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	if s.panicOnListConfigs {
		panic("simulated ListDynamicSecretConfigs panic")
	}
	return s.configs, nil
}

func (s *cascadePanicSpy) ListDynamicSecretLeases(_ context.Context, _ uint) ([]*models.DynamicSecretLease, error) {
	if s.panicOnListLeases {
		panic("simulated ListDynamicSecretLeases panic")
	}
	return nil, nil
}

func (s *cascadePanicSpy) GetDynamicSecretConfig(_ context.Context, id uint) (*models.DynamicSecretConfig, error) {
	for _, c := range s.configs {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, fmt.Errorf("config %d not found", id)
}

func (s *cascadePanicSpy) LogAuditEvent(_ context.Context, event *models.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func TestDeleteProject_CascadePanicInListConfigs_StillReturnsNil(t *testing.T) {
	t.Parallel()
	spy := &cascadePanicSpy{panicOnListConfigs: true}
	c := core.NewKeyorixCore(spy)

	err := c.DeleteProject(context.Background(), 0, 7, false)
	require.NoError(t, err, "the project delete already committed — a panic in the best-effort post-commit cascade must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, "dynamic_secret.project_cascade_failed", spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated ListDynamicSecretConfigs panic",
		"the audit event must include the panic value, not just a generic message")
}

func TestDeleteProject_CascadePanicInRevokeLeases_StillReturnsNil(t *testing.T) {
	t.Parallel()
	spy := &cascadePanicSpy{
		panicOnListLeases: true,
		configs:           []*models.DynamicSecretConfig{{ID: 5, ProjectID: 7}},
	}
	c := core.NewKeyorixCore(spy)

	err := c.DeleteProject(context.Background(), 0, 7, false)
	require.NoError(t, err, "the project delete already committed — a panic revoking leases must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, "dynamic_secret.project_cascade_failed", spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated ListDynamicSecretLeases panic")
}

// TestDeleteProject_PreCommitPanic_StillPropagates proves the recover added for X1
// is scoped to the post-commit cascade only: a panic from the guard+cascade
// primitive itself (DeleteProjectIfEmpty, which runs and commits BEFORE
// revokeProjectDynamicSecretLeases is ever called) must still propagate uncaught,
// so the transaction is not committed and the caller sees a failure — not be
// silently turned into a false "success".
func TestDeleteProject_PreCommitPanic_StillPropagates(t *testing.T) {
	t.Parallel()
	spy := &cascadePanicSpy{panicOnGuard: true}
	c := core.NewKeyorixCore(spy)

	assert.Panics(t, func() {
		_ = c.DeleteProject(context.Background(), 0, 7, false)
	}, "a pre-commit panic must not be recovered by the post-commit cascade's recover")
	assert.Empty(t, spy.auditEvents, "the post-commit cascade must never run if the pre-commit guard panicked")
}

func TestDeleteProject_CascadeNoPanic_NoCascadeFailedAudit(t *testing.T) {
	t.Parallel()
	spy := &cascadePanicSpy{}
	c := core.NewKeyorixCore(spy)

	require.NoError(t, c.DeleteProject(context.Background(), 0, 7, false))
	for _, e := range spy.auditEvents {
		assert.NotEqual(t, "dynamic_secret.project_cascade_failed", e.EventType, "a normal cascade with no configs must not write a cascade_failed event")
	}
}
