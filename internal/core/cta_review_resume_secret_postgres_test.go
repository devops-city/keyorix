// cta_review_resume_secret_postgres_test.go — #2794: ResumeSecret re-activates a
// secret_nodes row, so it races DeleteEnvironment/DeleteProject like CreateSecret and
// RestoreSecret do.
//
// DeleteEnvironment's guard counts only ACTIVE secrets, so an environment holding a
// SUSPENDED secret is deletable. ResumeSecret used to read the secret, then flip it to
// active with no parent check at all, which left a live secret inside a deleted
// environment (GetSecret does not check environment liveness).
//
// The interleaving is forced with replica B running in a goroutine and A's GORM hook
// waiting for it: B must be asynchronous because the fixed ResumeSecret holds the
// environment's named lock while it writes, so a synchronous B (the beforeA idiom used
// elsewhere) would block on A's lock and deadlock by design. The assertion is the end
// state, not either replica's returned error: either ordering is legal, but a live
// secret under a deleted environment or project is not.
package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// suspendedFixtureSecret seeds a live secret and suspends it through replica setup.
func (f *ctaReview) suspendedFixtureSecret(name string) *models.SecretNode {
	f.t.Helper()
	s := &models.SecretNode{
		Name: name, ProjectID: f.projectID, EnvironmentID: f.envID, IsSecret: true,
		OwnerID: f.adminID, Status: SecretStatusActive,
	}
	require.NoError(f.t, f.setupDB.Create(s).Error)
	_, err := f.setup.SuspendSecret(f.ctx, s.ID, f.adminID, "incident")
	require.NoError(f.t, err)
	return s
}

func TestCTAReview_ResumeSecret_vs_DeleteEnvironment_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s := f.suspendedFixtureSecret("cta-resume-env")

	delDone := make(chan error, 1)
	fired := f.beforeA("update", "secret_nodes", func() {
		go func() { delDone <- f.coreB.DeleteEnvironment(f.ctx, f.envID) }()
		// Give B time to finish if nothing stops it. A fixed ResumeSecret holds the
		// environment lock here, so B is still waiting when this returns; an unfixed one
		// lets B delete the environment first. Only the end state is asserted, so the
		// length of this wait affects which ordering is exercised, not correctness.
		time.Sleep(500 * time.Millisecond)
	})

	_, resumeErr := f.coreA.ResumeSecret(f.ctx, s.ID, f.adminID)
	delErr := <-delDone

	require.True(t, fired(), "replica A never reached its status UPDATE — the interleaving under test never happened")

	envLive := f.countLive(&models.Environment{}, "id = ? AND deleted_at IS NULL", f.envID)
	secretActive := f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NULL AND status = ?", s.ID, SecretStatusActive)
	assert.False(t, envLive == 0 && secretActive == 1,
		"an ACTIVE secret must not exist inside a deleted environment (resume err: %v, env delete err: %v)", resumeErr, delErr)
	// At least one side must have yielded; both succeeding is the orphan.
	assert.True(t, resumeErr != nil || delErr != nil,
		"resume and environment delete cannot both succeed against the same suspended secret")
}

func TestCTAReview_ResumeSecret_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s := f.suspendedFixtureSecret("cta-resume-project")

	var delErr error
	fired := f.beforeA("update", "secret_nodes", func() {
		delErr = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true)
	})

	_, resumeErr := f.coreA.ResumeSecret(f.ctx, s.ID, f.adminID)

	require.True(t, fired(), "replica A never reached its status UPDATE — the interleaving under test never happened")
	f.requireProjectDeleted(delErr)
	assert.Zero(t, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NULL", s.ID),
		"no live secret may remain under a deleted project (resume err: %v)", resumeErr)
}
