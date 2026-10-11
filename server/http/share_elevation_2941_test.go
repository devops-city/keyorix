// share_elevation_2941_test.go — #2976 (the demo's share step got a bare 403) and
// #2941 (Andrei's 2026-10-10 decision: a share MAY elevate a project member's access
// on that one secret), driven end-to-end through the real HTTP router with real
// session tokens: auth middleware -> RequireScopedSecretPermission -> handler -> core.
//
// The demo state these tests rebuild is exactly what scripts/demo/up.sh seeds: the
// bootstrap admin holds only the GLOBAL admin role, creates project backend-api and a
// secret in it (so the admin OWNS it), and alice is project_viewer on backend-api.
//
// #2976's cause: ShareSecret's first gate (requireLiveOwnerAuthority) requires the
// owner to be a live MEMBER of the secret's project, and a global grant makes nobody
// a member of any project (project_membership_definition.go). The admin owns the
// secret but is not a member of backend-api, so every client got
// "Not authorized to share this secret" with no hint. The rule stays (RBAC-001,
// QUICK_START "Sharing"); the refusal now says why, and the demo seed makes the
// admin a member.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const shareDemoPassword = "Qr7#Kp2$Lm5@Vn9!"

type shareDemo struct {
	c         *core.KeyorixCore
	srv       *httptest.Server
	adminID   uint
	adminTok  string
	aliceID   uint
	aliceTok  string
	bobID     uint
	projectID uint
	secretID  uint
}

// newShareDemo rebuilds scripts/demo/up.sh's seeded state (see the file header).
func newShareDemo(t *testing.T) *shareDemo {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newFullSchemaTestCore(t)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@keyorix.demo",
		Password: shareDemoPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "admin@keyorix.demo")
	require.NoError(t, err)

	project, err := c.CreateProject(ctx, "backend-api", "Backend API")
	require.NoError(t, err)
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	var envID uint
	for _, e := range envs {
		if e.ProjectID == project.ID {
			envID = e.ID
			break
		}
	}
	require.NotZero(t, envID, "backend-api must have a seeded environment")

	alice, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "alice", Email: "alice@keyorix.demo", DisplayName: "Alice", Password: shareDemoPassword,
	})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, admin.ID, project.ID, alice.ID, "project_viewer", false))
	bob, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "bob", Email: "bob@keyorix.demo", DisplayName: "Bob", Password: shareDemoPassword,
	})
	require.NoError(t, err)

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "db-password", Value: []byte("demo-db-pass-v1"),
		ProjectID: project.ID, EnvironmentID: envID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	login := func(username string) string {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: shareDemoPassword})
		require.NoError(t, lerr)
		return sess.SessionToken
	}
	srv := newSecretsMachineTestServer(t, c)
	t.Cleanup(srv.Close)
	return &shareDemo{
		c: c, srv: srv,
		adminID: admin.ID, adminTok: login("admin"),
		aliceID: alice.ID, aliceTok: login("alice"),
		bobID: bob.ID, projectID: project.ID, secretID: secret.ID,
	}
}

// makeAdminMember is the demo-seed fix: give the owner a project role so they are a
// live member of the secret's project and may share it.
func (d *shareDemo) makeAdminMember(t *testing.T) {
	t.Helper()
	require.NoError(t, d.c.AddProjectMember(context.Background(), d.adminID, d.projectID, d.adminID, "project_admin", false))
}

func (d *shareDemo) share(t *testing.T, tok string, recipientID uint, permission string) (int, map[string]interface{}) {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"recipient_id":%d,"is_group":false,"permission":%q}`, recipientID, permission))
	code, raw := doMachineRequest(t, d.srv, tok, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", d.secretID), body)
	var out map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &out)
	return code, out
}

func (d *shareDemo) shareOK(t *testing.T, recipientID uint, permission string) uint {
	t.Helper()
	code, out := d.share(t, d.adminTok, recipientID, permission)
	require.Equal(t, http.StatusCreated, code, "share must succeed: %v", out)
	data, ok := out["data"].(map[string]interface{})
	require.True(t, ok, "share response must carry data: %v", out)
	return uint(data["id"].(float64))
}

func (d *shareDemo) updateValue(t *testing.T, tok, value string) (int, string) {
	t.Helper()
	return doMachineRequest(t, d.srv, tok, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", d.secretID),
		[]byte(fmt.Sprintf(`{"value":%q}`, value)))
}

// TestShare2976_OwnerWhoIsNotAProjectMember_IsToldWhy reproduces the demo case of
// #2976 exactly: the global-only admin owns db-password and shares it with alice
// (a project_viewer of backend-api). The refusal must say the sharer is not a
// member of the secret's project, not a bare "Not authorized".
func TestShare2976_OwnerWhoIsNotAProjectMember_IsToldWhy(t *testing.T) {
	d := newShareDemo(t)

	code, out := d.share(t, d.adminTok, d.aliceID, "read")
	require.Equal(t, http.StatusForbidden, code, "the live-owner-is-a-member rule stays (RBAC-001): %v", out)
	assert.Contains(t, out["message"], "not a member of this secret's project",
		"#2976: the refusal must name the reason (the owner is not a project member), got %v", out)

	// The demo-seed fix: once the owner holds a project role the same share works.
	d.makeAdminMember(t)
	code, out = d.share(t, d.adminTok, d.aliceID, "read")
	assert.Equal(t, http.StatusCreated, code, "owner who is a project member may share with a member: %v", out)
}

// TestShare2976_RecipientWhoIsNotAProjectMember_IsToldWhy: shares never apply to
// non-members, and the refusal says so (bob holds no role in backend-api).
func TestShare2976_RecipientWhoIsNotAProjectMember_IsToldWhy(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)

	code, out := d.share(t, d.adminTok, d.bobID, "read")
	require.Equal(t, http.StatusForbidden, code, "%v", out)
	assert.Contains(t, out["message"], "recipient is not a member of this secret's project", "%v", out)
}

// TestShareElevation2941_WriteShareLetsViewerUpdate_RevokeRemovesExactlyThat is the
// decision itself: a project_viewer shared with write can update that one secret;
// revoking the share removes exactly the elevation (the role's read stays).
func TestShareElevation2941_WriteShareLetsViewerUpdate_RevokeRemovesExactlyThat(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)

	code, raw := d.updateValue(t, d.aliceTok, "alice-before-share")
	require.Equal(t, http.StatusForbidden, code, "a viewer without a share cannot update: %s", raw)

	shareID := d.shareOK(t, d.aliceID, "write")
	code, raw = d.updateValue(t, d.aliceTok, "alice-via-write-share")
	require.Equal(t, http.StatusOK, code, "#2941: a write share elevates a viewer to update this secret: %s", raw)

	code, raw = doMachineRequest(t, d.srv, d.adminTok, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", shareID), nil)
	require.Equal(t, http.StatusNoContent, code, "owner revokes the share: %s", raw)

	code, raw = d.updateValue(t, d.aliceTok, "alice-after-revoke")
	assert.Equal(t, http.StatusForbidden, code, "revoke must remove the elevation: %s", raw)
	code, raw = doMachineRequest(t, d.srv, d.aliceTok, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", d.secretID), nil)
	assert.Equal(t, http.StatusOK, code, "revoke removes exactly the elevation, not the role's read: %s", raw)
}

// TestShareElevation2941_ReadShareDoesNotGrantWrite: the share level bounds the
// elevation.
func TestShareElevation2941_ReadShareDoesNotGrantWrite(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)
	d.shareOK(t, d.aliceID, "read")

	code, raw := d.updateValue(t, d.aliceTok, "should-not-land")
	assert.Equal(t, http.StatusForbidden, code, "a read share never grants write: %s", raw)
}

// TestShareElevation2941_WriteShareNeverGrantsDeleteManageOrShare: share levels are
// read|write only, so a share never grants delete, secrets.manage or the right to
// re-share.
func TestShareElevation2941_WriteShareNeverGrantsDeleteManageOrShare(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)
	d.shareOK(t, d.aliceID, "write")

	code, raw := doMachineRequest(t, d.srv, d.aliceTok, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", d.secretID), nil)
	assert.Equal(t, http.StatusForbidden, code, "write share must not grant delete: %s", raw)
	code, raw = doMachineRequest(t, d.srv, d.aliceTok, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", d.secretID), nil)
	assert.Equal(t, http.StatusForbidden, code, "write share must not grant secrets.manage: %s", raw)
	code, out := d.share(t, d.aliceTok, d.adminID, "read")
	assert.Equal(t, http.StatusForbidden, code, "write share must not grant re-sharing: %v", out)
}

// TestShareElevation2941_ExpiredShareGrantsNothing: an expired share elevates
// nothing even before the sweeper reclaims the row.
func TestShareElevation2941_ExpiredShareGrantsNothing(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)
	shareID := d.shareOK(t, d.aliceID, "write")

	ctx := context.Background()
	rec, err := d.c.Storage().GetShareRecord(ctx, shareID)
	require.NoError(t, err)
	past := time.Now().Add(-time.Minute)
	rec.ExpiresAt = &past
	_, err = d.c.Storage().UpdateShareRecord(ctx, rec)
	require.NoError(t, err)

	code, raw := d.updateValue(t, d.aliceTok, "should-not-land")
	assert.Equal(t, http.StatusForbidden, code, "an expired share grants nothing: %s", raw)
}

// TestShareElevation2941_ShareStopsApplyingWhenRecipientLeavesProject: shares never
// apply to non-members, at access time too. RemoveProjectMember deletes role grants
// and ACLs but not share rows, so without the access-time membership check a removed
// member's leftover write share would become their ONLY grant and still work.
func TestShareElevation2941_ShareStopsApplyingWhenRecipientLeavesProject(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)
	d.shareOK(t, d.aliceID, "write")

	require.NoError(t, d.c.RemoveProjectMember(context.Background(), d.adminID, d.projectID, d.aliceID))

	code, raw := d.updateValue(t, d.aliceTok, "should-not-land")
	assert.Equal(t, http.StatusForbidden, code, "a non-member's share must not apply: %s", raw)
	code, raw = doMachineRequest(t, d.srv, d.aliceTok, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", d.secretID), nil)
	assert.Equal(t, http.StatusForbidden, code, "a non-member's share must not grant read either: %s", raw)
}

// TestShareElevation2941_AuditCarriesShareID: share create/revoke and every action
// the share elevated are audited with the share id.
func TestShareElevation2941_AuditCarriesShareID(t *testing.T) {
	d := newShareDemo(t)
	d.makeAdminMember(t)
	shareID := d.shareOK(t, d.aliceID, "write")
	code, raw := d.updateValue(t, d.aliceTok, "alice-via-write-share")
	require.Equal(t, http.StatusOK, code, raw)
	code, raw = doMachineRequest(t, d.srv, d.adminTok, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", shareID), nil)
	require.Equal(t, http.StatusNoContent, code, raw)

	events := shareAuditEvents(t, d.c, d.secretID)
	marker := fmt.Sprintf("share %d", shareID)
	for _, want := range []string{"share_created", "share_access_elevated", "share_revoked"} {
		ev, ok := events[want]
		if assert.True(t, ok, "missing %s audit event; have %v", want, events) {
			assert.Contains(t, ev.Description, marker, "%s must carry the share id", want)
		}
	}
	if ev, ok := events["share_access_elevated"]; ok {
		require.NotNil(t, ev.UserID)
		assert.Equal(t, d.aliceID, *ev.UserID, "the elevated actor is the recipient")
	}
}

func shareAuditEvents(t *testing.T, c *core.KeyorixCore, secretID uint) map[string]*models.AuditEvent {
	t.Helper()
	rows, _, err := c.Storage().GetAuditLogs(context.Background(), &storage.AuditFilter{SecretID: &secretID, Page: 1, PageSize: 500})
	require.NoError(t, err)
	out := make(map[string]*models.AuditEvent, len(rows))
	for _, r := range rows {
		out[r.EventType] = r
	}
	return out
}
