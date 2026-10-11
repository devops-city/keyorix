// secret_listing_scoped_share_permission_test.go — CI-FIX-4: a project-scoped listing tells
// a share recipient what their share allows.
//
// ListSecretsInScopeWithSharingInfo used to look up the caller's shares only when the filter
// had no project, so GET /secrets?project_id=N (what a project's Secrets tab calls) returned
// an empty user_permission for a recipient of a write share. The web UI hides Edit / Rotate
// from a user whose roles lack secrets.write (#3047) and had nothing else to go on, so the
// elevation #2941 grants was real at the API and unreachable in the UI.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListReadableSecrets_ProjectScopedListingCarriesTheCallersSharePermission(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	_, shared := seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)
	projectID := uint(1)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20, ProjectID: &projectID})
	require.NoError(t, err)

	perm := map[string]string{}
	for _, s := range resp.Secrets {
		perm[s.Name] = s.UserPermission
	}
	assert.Equal(t, "read", perm[shared],
		"a project-scoped listing must carry the recipient's share permission; got %v", perm)
	assert.Equal(t, "", perm["neither"],
		"a secret the caller holds no share on carries no permission (role-only visibility); got %v", perm)
	assert.Equal(t, int64(3), resp.Total, "decorating must not add or drop rows")
}
