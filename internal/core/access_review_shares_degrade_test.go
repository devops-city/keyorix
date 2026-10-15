package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// #483: GenerateProjectAccessReview previously silently `continue`d past a secret
// whose ListSharesBySecret call errored — that secret's direct/group shares were
// dropped from the report with no signal, the identical fail-open shape #453 fixed
// for LastUserSecretActivity, but in a SEPARATE call in the SAME function. A
// transient error reading ONE secret's shares must flip Degraded while every OTHER
// secret's shares are still correctly reported.
func TestGenerateProjectAccessReview_DegradedOnShareLookupError(t *testing.T) {
	t.Parallel()
	const proj = uint(2)
	ctx := context.Background()

	ms := &MockStorage{}
	ms.On("ListProjectRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{}, nil)
	ms.On("ListProjectMachineRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{}, nil)
	ms.On("ListSecrets", ctx, mock.Anything).Return([]*models.SecretNode{
		{ID: 500, ProjectID: proj, Name: "good-secret"},
		{ID: 501, ProjectID: proj, Name: "bad-secret"},
	}, int64(2), nil)
	// The batched lookup fails; the per-secret fallback then isolates the bad secret.
	ms.On("ListSharesBySecretIDs", ctx, []uint{500, 501}, mock.Anything).Return(nil, errors.New("connection reset"))
	ms.On("ListSharesBySecret", ctx, uint(500), mock.Anything).Return([]*models.ShareRecord{
		{SecretID: 500, RecipientID: 100, IsGroup: true, Permission: "write"},
	}, nil)
	ms.On("ListSharesBySecret", ctx, uint(501), mock.Anything).Return(nil, errors.New("connection reset"))
	ms.On("GetGroupNamesByIDs", ctx, []uint{100}).Return(map[uint]string{100: "devs"}, nil)
	ms.On("LastUserSecretActivity", ctx, proj).Return(map[uint]time.Time{}, nil)

	c := NewKeyorixCore(ms)
	report, err := c.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)

	assert.True(t, report.Degraded, "a failed per-secret share lookup must flip Degraded")
	require.NotEmpty(t, report.DegradedReasons)
	assert.Contains(t, report.DegradedReasons[0], "shares:secret=501")

	// The OTHER secret's share is still correctly reported.
	var found bool
	for _, e := range report.Entries {
		if e.Source == "group_share" && e.SecretID == 500 && e.PrincipalName == "devs" && e.AccessLevel == "write" {
			found = true
		}
		assert.NotEqual(t, uint(501), e.SecretID, "the errored secret contributes no share entries")
	}
	assert.True(t, found, "secret 500's group share must still appear in the report")

	ms.AssertExpectations(t)
}
