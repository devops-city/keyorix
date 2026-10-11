// share_recipients_search_test.go — SHARE-2: a project-only admin can find share
// recipients. GET /api/v1/projects/{id}/share-recipients, driven through the real
// router with real session tokens (auth middleware -> RequireScopedPermission ->
// handler -> core.SearchShareRecipients).
//
// Before it, the Share dialog searched GET /api/v1/users, gated on GLOBAL users.read,
// so a project_admin of P (who may share P's secrets) could not find anyone:
// E2E-SHARE-1's spec had to give its owner the global system_auditor role.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recipientFixture struct {
	d *shareDemo
	// projectID (d.projectID) is P: the owner is its project_admin and nothing else.
	otherProjectID  uint
	ownerID         uint
	ownerTok        string
	writerTok       string // custom role at P: secrets.read + secrets.write, no users.read
	otherAdminTok   string // project_admin of the other project only
	outsiderTok     string // no role anywhere but the install baseline
	globalWriterTok string // the custom role at the GLOBAL scope: passes the route gate, not a member
	viewerTok       string // alice, project_viewer at P (no secrets.write)
	ids             map[string]uint
}

// newRecipientFixture extends the demo seed with every kind of user the search must
// include or leave out.
func newRecipientFixture(t *testing.T) *recipientFixture {
	t.Helper()
	d := newShareDemo(t)
	ctx := context.Background()
	c := d.c
	ids := map[string]uint{"alice": d.aliceID, "bob": d.bobID}

	mk := func(username, display string) uint {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{
			Username: username, Email: username + "@keyorix.demo", DisplayName: display, Password: shareDemoPassword,
		})
		require.NoError(t, err)
		ids[username] = u.ID
		return u.ID
	}
	member := func(userID uint, role string) {
		require.NoError(t, c.AddProjectMember(ctx, d.adminID, d.projectID, userID, role, false))
	}

	other, err := c.CreateProject(ctx, "payments", "Payments")
	require.NoError(t, err)

	owner := mk("olga", "Olga Owner")
	member(owner, "project_admin")

	// Member through a group only.
	carol := mk("carol", "Carol Group")
	viewerRole, err := c.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	group, err := c.Storage().CreateGroup(ctx, &models.Group{Name: "p-readers"})
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRoleToGroup(ctx, group.ID, viewerRole.ID, storage.Scope{ProjectID: d.projectID}))
	require.NoError(t, c.Storage().AddUserToGroup(ctx, carol, group.ID, 0))

	// Members that are not ACTIVE.
	member(mk("dave", "Dave Suspended"), "project_viewer")
	require.NoError(t, c.SuspendUser(ctx, d.adminID, ids["dave"]))
	member(mk("erin", "Erin Deleted"), "project_viewer")
	require.NoError(t, c.DeleteUser(ctx, d.adminID, ids["erin"]))
	member(mk("ivan", "Ivan Inactive"), "project_viewer")
	ivan, err := c.Storage().GetUser(ctx, ids["ivan"])
	require.NoError(t, err)
	ivan.IsActive = false
	_, err = c.Storage().UpdateUser(ctx, ivan)
	require.NoError(t, err)

	// Outside P: a member of the other project, and nobody's member at all.
	frank := mk("frank", "Frank Payments")
	require.NoError(t, c.AddProjectMember(ctx, d.adminID, other.ID, frank, "project_viewer", false))
	otherAdmin := mk("pavel", "Pavel Payments Admin")
	require.NoError(t, c.AddProjectMember(ctx, d.adminID, other.ID, otherAdmin, "project_admin", false))
	mk("oscar", "Oscar Outsider")

	// A sharer who may NOT read member emails: secrets.read + secrets.write only.
	perms, err := c.Storage().ListPermissions(ctx)
	require.NoError(t, err)
	var permIDs []uint
	for _, p := range perms {
		if p.Name == "secrets.read" || p.Name == "secrets.write" {
			permIDs = append(permIDs, p.ID)
		}
	}
	require.Len(t, permIDs, 2)
	writerRole, _, err := c.CreateRole(ctx, d.adminID, "secret_writer", "write secrets, no user directory", permIDs)
	require.NoError(t, err)
	writer := mk("wendy", "Wendy Writer")
	require.NoError(t, c.Storage().AssignRole(ctx, writer, writerRole.ID, storage.Scope{ProjectID: d.projectID}))
	globalWriter := mk("gina", "Gina Global Writer")
	require.NoError(t, c.Storage().AssignRole(ctx, globalWriter, writerRole.ID, storage.Scope{}))

	login := func(username string) string {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: shareDemoPassword})
		require.NoError(t, lerr)
		return sess.SessionToken
	}
	return &recipientFixture{
		d: d, otherProjectID: other.ID, ownerID: owner,
		ownerTok: login("olga"), writerTok: login("wendy"), otherAdminTok: login("pavel"),
		outsiderTok: login("oscar"), globalWriterTok: login("gina"), viewerTok: d.aliceTok, ids: ids,
	}
}

type recipientResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Recipients []map[string]interface{} `json:"recipients"`
		Total      int                      `json:"total"`
		Page       int                      `json:"page"`
		PageSize   int                      `json:"page_size"`
	} `json:"data"`
}

func (f *recipientFixture) search(t *testing.T, tok string, projectID uint, query string) (int, recipientResponse, string) {
	t.Helper()
	code, raw := doMachineRequest(t, f.d.srv, tok, http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%d/share-recipients%s", projectID, query), nil)
	var out recipientResponse
	_ = json.Unmarshal([]byte(raw), &out)
	return code, out, raw
}

func usernames(rs []map[string]interface{}) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, fmt.Sprint(r["username"]))
	}
	sort.Strings(out)
	return out
}

// The bug, stated as the user hits it: the project-only owner cannot list users.
func TestShareRecipients_ProjectOnlyAdminCannotUseGlobalUserList(t *testing.T) {
	f := newRecipientFixture(t)
	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodGet, "/api/v1/users?search=al", nil)
	assert.Equal(t, http.StatusForbidden, code, "GET /users stays a global users.read route: %s", raw)
}

func TestShareRecipients_ProjectOnlyAdminFindsActiveMembersOfP(t *testing.T) {
	f := newRecipientFixture(t)
	code, out, raw := f.search(t, f.ownerTok, f.d.projectID, "")
	require.Equal(t, http.StatusOK, code, raw)
	// alice: direct project_viewer; carol: via a group; olga: the caller herself;
	// wendy: custom role. admin holds only a GLOBAL role, so is not a member.
	assert.Equal(t, []string{"alice", "carol", "olga", "wendy"}, usernames(out.Data.Recipients), raw)
	assert.Equal(t, 4, out.Data.Total)
	for _, absent := range []string{"bob", "dave", "erin", "ivan", "frank", "pavel", "oscar", "admin"} {
		assert.NotContains(t, raw, `"`+absent+`"`, "%s is not an active member of P", absent)
	}
}

func TestShareRecipients_PrefixMatchesUsernameAndDisplayName(t *testing.T) {
	f := newRecipientFixture(t)
	cases := map[string][]string{
		"?q=al":    {"alice"},
		"?q=AL":    {"alice"},
		"?q=group": {"carol"}, // second word of "Carol Group"
		"?q=w":     {"wendy"},
		"?q=fr":    {}, // frank is in the other project only
		"?q=lice":  {}, // prefix, not substring
		"?q=dave":  {}, // suspended
	}
	for q, want := range cases {
		code, out, raw := f.search(t, f.ownerTok, f.d.projectID, q)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, want, usernames(out.Data.Recipients), "query %s: %s", q, raw)
	}
}

func TestShareRecipients_Paginates(t *testing.T) {
	f := newRecipientFixture(t)
	var seen []string
	for page := 1; page <= 3; page++ {
		code, out, raw := f.search(t, f.ownerTok, f.d.projectID, fmt.Sprintf("?page=%d&page_size=2", page))
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, 4, out.Data.Total)
		assert.Equal(t, 2, out.Data.PageSize)
		seen = append(seen, usernames(out.Data.Recipients)...)
	}
	sort.Strings(seen)
	assert.Equal(t, []string{"alice", "carol", "olga", "wendy"}, seen, "pages must partition the result")
}

// Minimal fields: id, username, display_name. Email only for a caller who may
// already read P's member emails (users.read at P, the gate of
// GET /projects/{id}/members); and an email prefix never matches for anyone else.
func TestShareRecipients_ResultFieldsAreMinimal(t *testing.T) {
	f := newRecipientFixture(t)

	code, out, raw := f.search(t, f.writerTok, f.d.projectID, "?q=alice")
	require.Equal(t, http.StatusOK, code, raw)
	require.Len(t, out.Data.Recipients, 1, raw)
	keys := make([]string, 0)
	for k := range out.Data.Recipients[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"display_name", "id", "username"}, keys, "no email for a caller without users.read: %s", raw)
	assert.NotContains(t, raw, "@keyorix.demo")
	_, out, raw = f.search(t, f.writerTok, f.d.projectID, "?q=alice@")
	assert.Empty(t, out.Data.Recipients, "an email prefix must not match when emails are hidden: %s", raw)

	// project_admin holds users.read at P: it already sees these emails on
	// GET /projects/{id}/members, so it gets them here too.
	_, out, raw = f.search(t, f.ownerTok, f.d.projectID, "?q=alice")
	require.Len(t, out.Data.Recipients, 1, raw)
	assert.Equal(t, "alice@keyorix.demo", out.Data.Recipients[0]["email"])
	for _, forbidden := range []string{"role", "password", "account_state", "is_active", "mfa", "last_login"} {
		assert.NotContains(t, raw, forbidden)
	}
}

// A non-member — an admin of another project, or a user with no role — gets 403 with
// the reason, identical whether or not the project exists (INV-HTTP-08).
func TestShareRecipients_NonMemberGets403WithReason(t *testing.T) {
	f := newRecipientFixture(t)
	for name, tok := range map[string]string{
		"other-project admin":          f.otherAdminTok,
		"outsider":                     f.outsiderTok,
		"viewer without secrets.write": f.viewerTok,
		// Passes the route gate (global secrets.write) but is not a member of P and
		// holds no global users.read: refused by core's owner-must-be-a-member rule.
		"global writer, not a member": f.globalWriterTok,
	} {
		code, out, raw := f.search(t, tok, f.d.projectID, "?q=a")
		assert.Equal(t, http.StatusForbidden, code, "%s: %s", name, raw)
		assert.Equal(t, core.ShareRecipientSearchDeniedMessage, out.Message, "%s: %s", name, raw)
		assert.NotContains(t, raw, "alice", name)
	}
	_, _, existing := f.search(t, f.outsiderTok, f.d.projectID, "")
	_, _, missing := f.search(t, f.outsiderTok, 999999, "")
	assert.JSONEq(t, existing, missing, "403 for an existing project and a missing one must be identical")

	// The other project's admin searches their OWN project and sees its members only.
	code, out, raw := f.search(t, f.otherAdminTok, f.otherProjectID, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []string{"frank", "pavel"}, usernames(out.Data.Recipients))
}

// Global admins keep today's behaviour: global users.read already lists every user,
// so a global admin who is not a member of P may search P too (with emails). Sharing
// itself still needs membership (ShareSecret's owner rule).
func TestShareRecipients_GlobalAdminKeepsAccess(t *testing.T) {
	f := newRecipientFixture(t)
	code, out, raw := f.search(t, f.d.adminTok, f.d.projectID, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []string{"alice", "carol", "olga", "wendy"}, usernames(out.Data.Recipients))
	assert.Contains(t, raw, "alice@keyorix.demo")
	code, raw = doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodGet, "/api/v1/users?search=al", nil)
	assert.Equal(t, http.StatusOK, code, "GET /users unchanged for a global admin: %s", raw)
}

// A recipient the search lists is one ShareSecret accepts, and one it leaves out is
// one ShareSecret refuses: the two agree because both ask IsProjectMember.
func TestShareRecipients_AgreesWithShareSecret(t *testing.T) {
	f := newRecipientFixture(t)
	ctx := context.Background()
	c := f.d.c
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	var envID uint
	for _, e := range envs {
		if e.ProjectID == f.d.projectID {
			envID = e.ID
			break
		}
	}
	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "olga-secret", Value: []byte("v1"), ProjectID: f.d.projectID, EnvironmentID: envID,
		Type: "generic", CreatedBy: "olga", OwnerID: f.ownerID,
	})
	require.NoError(t, err)
	share := func(recipient uint) int {
		code, _ := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secret.ID),
			[]byte(fmt.Sprintf(`{"recipient_id":%d,"is_group":false,"permission":"read"}`, recipient)))
		return code
	}
	_, out, _ := f.search(t, f.ownerTok, f.d.projectID, "?q=carol")
	require.Len(t, out.Data.Recipients, 1)
	assert.Equal(t, http.StatusCreated, share(uint(out.Data.Recipients[0]["id"].(float64))), "a listed recipient (via group) is shareable")
	assert.Equal(t, http.StatusForbidden, share(f.ids["frank"]), "an unlisted non-member is refused by ShareSecret too")
}
