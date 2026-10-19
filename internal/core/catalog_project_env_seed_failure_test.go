package core

// catalog_project_env_seed_failure_test.go covers item 4's reported gap: if CreateProject's
// default-environment seeding fails part-way, what's left behind? The project row commits
// (non-fatal by design, server/faultops's opScopedBestEffortTables entry, #2350/#2252) but
// the failure was previously only a log.Printf -- invisible to the audit trail, the API
// response, or any automated reconciliation sweep. These tests prove the project survives
// with exactly the other environments seeded, the gap is now audited
// (EventProjectEnvironmentSeedFailed), and the audit write cannot deadlock against the
// outer transaction it reports on (a real risk under newBootstrappedCore's
// MaxOpenConns(1) SQLite pool -- see reportProjectEnvironmentSeedFailures's doc comment).

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failEnvStorage fails CreateEnvironment for exactly one named environment and records every
// LogAuditEvent call, mirroring failOnceProjectMemberStorage's re-wrap-across-WithTransaction
// idiom (project_members_atomicity_test.go) so the fault also fires on the transaction-scoped
// handle CreateProject's seeding loop actually uses.
func failEnvStorage(inner storage.Storage, failEnvName string, auditEvents *[]*models.AuditEvent) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		CreateEnvironment: func(next storage.Storage, ctx context.Context, env *models.Environment) (*models.Environment, error) {
			if env.Name == failEnvName {
				return nil, errors.New("injected fault: CreateEnvironment " + failEnvName)
			}
			return next.CreateEnvironment(ctx, env)
		},
		LogAuditEvent: func(next storage.Storage, ctx context.Context, event *models.AuditEvent) error {
			*auditEvents = append(*auditEvents, event)
			return next.LogAuditEvent(ctx, event)
		},
	})
}

// TestCreateProject_PartialEnvironmentSeedFailure_AuditedAndRecoverable is the red-proof for
// #4: before this fix, a failed default-environment seed left the gap undiscoverable outside
// server logs. Red without EventProjectEnvironmentSeedFailed: zero matching audit events.
func TestCreateProject_PartialEnvironmentSeedFailure_AuditedAndRecoverable(t *testing.T) {
	c, base := newBootstrappedCore(t)
	var auditEvents []*models.AuditEvent
	c.storage = failEnvStorage(base, "staging", &auditEvents)

	ctx := context.Background()
	project, err := c.CreateProject(ctx, "demo-project", "")
	require.NoError(t, err, "the project row itself must still be created despite the seeding failure")
	require.NotNil(t, project)

	envs, err := base.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, e := range envs {
		names[e.Name] = true
	}
	assert.True(t, names["development"], "development should have seeded fine")
	assert.True(t, names["production"], "production should have seeded fine")
	assert.False(t, names["staging"], "staging should be exactly the one environment that failed to seed")

	var seedFailedEvents []*models.AuditEvent
	for _, e := range auditEvents {
		if e.EventType == EventProjectEnvironmentSeedFailed {
			seedFailedEvents = append(seedFailedEvents, e)
		}
	}
	require.Len(t, seedFailedEvents, 1, "exactly one seed-failure audit event, for the one environment that failed")
	assert.Equal(t, project.ID, *seedFailedEvents[0].ProjectID)
	assert.Contains(t, seedFailedEvents[0].Description, "staging")
	assert.Contains(t, seedFailedEvents[0].Description, "injected fault: CreateEnvironment staging")
	assert.Contains(t, seedFailedEvents[0].Description, "POST /projects",
		"the audit description must point at the recovery path, not just name the gap")

	// Recoverable: once the transient fault clears, the normal environment-creation path
	// (POST /projects/{id}/environments -> core.CreateEnvironment -> storage.CreateEnvironment,
	// not through this test's injected-fault wrapper) can fill the gap.
	_, err = base.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: project.ID})
	require.NoError(t, err, "the missing environment must be creatable via the ordinary path once the transient fault clears")
}

// TestCreateProjectWithEnvs_PartialEnvironmentSeedFailure_Audited is
// TestCreateProject_PartialEnvironmentSeedFailure_AuditedAndRecoverable's counterpart for the
// caller-specified-environments path (CreateProjectWithEnvs), which duplicated the exact same
// bug before this fix.
func TestCreateProjectWithEnvs_PartialEnvironmentSeedFailure_Audited(t *testing.T) {
	c, base := newBootstrappedCore(t)
	var auditEvents []*models.AuditEvent
	c.storage = failEnvStorage(base, "qa", &auditEvents)

	ctx := context.Background()
	project, err := c.CreateProjectWithEnvs(ctx, "custom-envs-project", "", []string{"dev", "qa", "prod"})
	require.NoError(t, err)
	require.NotNil(t, project)

	envs, err := base.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, e := range envs {
		names[e.Name] = true
	}
	assert.True(t, names["dev"])
	assert.True(t, names["prod"])
	assert.False(t, names["qa"], "qa should be the one environment that failed to seed")

	var seedFailedEvents []*models.AuditEvent
	for _, e := range auditEvents {
		if e.EventType == EventProjectEnvironmentSeedFailed {
			seedFailedEvents = append(seedFailedEvents, e)
		}
	}
	require.Len(t, seedFailedEvents, 1)
	assert.Contains(t, seedFailedEvents[0].Description, "qa")
}

// TestCreateProject_NoSeedFailure_NoSeedFailedAudit is the negative case: a normal create
// with no fault must never write EventProjectEnvironmentSeedFailed.
func TestCreateProject_NoSeedFailure_NoSeedFailedAudit(t *testing.T) {
	c, base := newBootstrappedCore(t)
	var auditEvents []*models.AuditEvent
	c.storage = failEnvStorage(base, "", &auditEvents)

	ctx := context.Background()
	project, err := c.CreateProject(ctx, "clean-project", "")
	require.NoError(t, err)

	envs, err := base.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 3, "all three default environments must have seeded")

	for _, e := range auditEvents {
		assert.NotEqual(t, EventProjectEnvironmentSeedFailed, e.EventType)
	}
}
