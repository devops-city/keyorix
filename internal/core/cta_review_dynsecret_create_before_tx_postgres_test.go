package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_CreateDynamicSecretConfig_DeleteProjectBeforeTx_CrossReplicaPostgres:
// B's DeleteProject commits after A's request validation but before A's
// create-config transaction has written or locked anything (the hook fires before A's
// config INSERT, the first statement of the transaction, so A holds no lock B needs
// and running B synchronously on A's goroutine cannot deadlock). The project is already
// gone when A inserts; the insert's own project re-check (lockLiveParent) must fail
// closed, and the whole transaction, insert included, must roll back: no config row
// of any kind for the deleted project, in particular no enabled one.
//
// Companion of TestCTAReview_CreateDynamicSecretConfig_vs_DeleteProject_CrossReplicaPostgres
// (B lands mid-transaction) and ..._DeleteProjectAfterInsert_... (B lands right after the INSERT).
func TestCTAReview_CreateDynamicSecretConfig_DeleteProjectBeforeTx_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	f.coreA.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	f.coreB.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	var errB error
	fired := f.beforeA("create", "dynamic_secret_configs", func() { errB = f.coreB.DeleteProject(f.ctx, f.projectID, true) })
	_, errA := f.coreA.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-dyn-before", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	t.Logf("CreateDynamicSecretConfig (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have run B's DeleteProject before A's config INSERT")
	require.NoError(t, errB)

	assert.Error(t, errA, "A must fail closed: its project was deleted before it inserted")
	assert.Zero(t, f.countLive(&models.DynamicSecretConfig{}, "project_id = ?", f.projectID),
		"orphan config: a dynamic-secret config row exists for a deleted project after A reported failure")
	assert.Zero(t, f.countLive(&models.DynamicSecretConfig{}, "project_id = ? AND disabled = ?", f.projectID, false),
		"#369 violated: an enabled dynamic-secret config exists in a deleted project")
}
