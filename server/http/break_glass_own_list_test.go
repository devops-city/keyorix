// break_glass_own_list_test.go — BREAKGLASS-OWN-1 (Andrei 2026-10-13: a member lists
// their OWN break-glass activations). GET /api/v1/projects/{id}/break-glass, driven
// through the real router with real session tokens, PATs and machine tokens
// (auth middleware -> handler -> core.ListBreakGlassActivationsForCaller).
//
// Before it, the route was gated on roles.read at the project, so a member who had
// just activated emergency access could not see their own activation (the CLI
// refused honestly since #2981). Now: roles.read lists every activation, unchanged;
// any other user lists only their own; nothing about anyone else's activations
// (rows, counts, existence) reaches them.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const bgOwnJustificationPrefix = "BREAKGLASS-OWN-1 drill by "

type bgOwnFixture struct {
	d                      *shareDemo
	paymentsID             uint
	aliceTok, bobTok       string // project_viewer at P (and alice at payments): no roles.read
	oscarTok               string // no project role anywhere
	aliceP, bobP, aliceRev uint   // activation ids at P (aliceRev: alice's, revoked by admin)
	aliceExpired, bobExp   uint   // rows at P whose TTL has lapsed (read as expired)
	alicePayments          uint   // alice's activation at payments
}

func newBGOwnFixture(t *testing.T) *bgOwnFixture {
	t.Helper()
	d := newShareDemo(t)
	ctx := context.Background()
	c := d.c
	c.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
	payments, err := c.CreateProject(ctx, "payments", "Payments")
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, d.adminID, d.projectID, d.bobID, "project_viewer", false))
	require.NoError(t, c.AddProjectMember(ctx, d.adminID, payments.ID, d.aliceID, "project_viewer", false))
	_, err = c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "oscar", Email: "oscar@keyorix.demo", DisplayName: "Oscar Outsider", Password: shareDemoPassword,
	})
	require.NoError(t, err)
	login := func(username string) string {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: shareDemoPassword})
		require.NoError(t, lerr)
		return sess.SessionToken
	}
	f := &bgOwnFixture{d: d, paymentsID: payments.ID, aliceTok: d.aliceTok, bobTok: login("bob"), oscarTok: login("oscar")}

	// TTL-lapsed rows, made FIRST: still "active" in storage and read as expired. The
	// one-active-row index is per (project, user), and the real activations below
	// reconcile these to expired before inserting their own.
	past := time.Now().Add(-2 * time.Hour)
	created := past.Add(-time.Hour)
	expired := func(userID uint, who string) uint {
		a, cerr := c.Storage().CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
			ProjectID: d.projectID, UserID: userID, RoleID: 1, RoleName: "project_developer",
			Justification: bgOwnJustificationPrefix + who, State: core.BreakGlassActive,
			ExpiresAt: &past, CreatedAt: created,
		})
		require.NoError(t, cerr)
		return a.ID
	}
	f.aliceExpired = expired(d.aliceID, "alice-expired")
	f.bobExp = expired(d.bobID, "bob-expired")

	activate := func(tok string, projectID uint, who string) uint {
		body := []byte(fmt.Sprintf(`{"justification":%q}`, bgOwnJustificationPrefix+who))
		code, raw := doMachineRequest(t, d.srv, tok, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/break-glass", projectID), body)
		require.Equal(t, http.StatusCreated, code, raw)
		var out struct {
			Data struct {
				Activation struct {
					ID uint `json:"id"`
				} `json:"activation"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		require.NotZero(t, out.Data.Activation.ID, raw)
		return out.Data.Activation.ID
	}
	// alice activates at P; the admin revokes it; she activates again.
	f.aliceRev = activate(f.aliceTok, d.projectID, "alice-revoked")
	code, raw := doMachineRequest(t, d.srv, d.adminTok, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/revoke", d.projectID, f.aliceRev), nil)
	require.Equal(t, http.StatusOK, code, raw)
	f.aliceP = activate(f.aliceTok, d.projectID, "alice")
	f.bobP = activate(f.bobTok, d.projectID, "bob")
	f.alicePayments = activate(f.aliceTok, payments.ID, "alice-payments")
	return f
}

type bgListResponse struct {
	Data struct {
		Activations []struct {
			ID            uint   `json:"id"`
			UserID        uint   `json:"user_id"`
			ProjectID     uint   `json:"project_id"`
			State         string `json:"state"`
			Justification string `json:"justification"`
			RoleName      string `json:"role_name"`
		} `json:"activations"`
		Count int    `json:"count"`
		Scope string `json:"scope"`
	} `json:"data"`
}

func (f *bgOwnFixture) list(t *testing.T, tok string, projectID uint) (int, bgListResponse, string) {
	t.Helper()
	code, raw := doMachineRequest(t, f.d.srv, tok, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/break-glass", projectID), nil)
	var out bgListResponse
	if code == http.StatusOK {
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	}
	return code, out, raw
}

func bgIDs(r bgListResponse) []uint {
	out := make([]uint, 0, len(r.Data.Activations))
	for _, a := range r.Data.Activations {
		out = append(out, a.ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedUints(in ...uint) []uint {
	sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
	return in
}

// The journey: alice activated, and now she can see it (with every own state).
func TestBreakGlassOwnList_MemberSeesOnlyOwnActivations(t *testing.T) {
	f := newBGOwnFixture(t)

	code, out, raw := f.list(t, f.aliceTok, f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, core.BreakGlassListScopeOwn, out.Data.Scope, raw)
	assert.Equal(t, sortedUints(f.aliceP, f.aliceRev, f.aliceExpired), bgIDs(out), raw)
	assert.Equal(t, 3, out.Data.Count, "count is alice's rows, not the project's: %s", raw)
	states := map[uint]string{}
	for _, a := range out.Data.Activations {
		assert.Equal(t, f.d.aliceID, a.UserID, raw)
		assert.Equal(t, f.d.projectID, a.ProjectID, raw)
		assert.Equal(t, "project_developer", a.RoleName, raw)
		states[a.ID] = a.State
	}
	assert.Equal(t, "active", states[f.aliceP], raw)
	assert.Equal(t, "revoked", states[f.aliceRev], raw)
	assert.Equal(t, "expired", states[f.aliceExpired], raw)
	// Member A cannot see member B's: no row, no justification, no id.
	assert.NotContains(t, raw, bgOwnJustificationPrefix+"bob", raw)
	assert.NotContains(t, raw, fmt.Sprintf(`"user_id":%d`, f.d.bobID), raw)

	// And B cannot see A's.
	code, out, raw = f.list(t, f.bobTok, f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, core.BreakGlassListScopeOwn, out.Data.Scope, raw)
	assert.Equal(t, sortedUints(f.bobP, f.bobExp), bgIDs(out), raw)
	assert.Equal(t, 2, out.Data.Count, raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix+"alice", raw)
}

// Callers with roles.read keep today's full list.
func TestBreakGlassOwnList_RolesReadSeesWholeProjectUnchanged(t *testing.T) {
	f := newBGOwnFixture(t)
	code, out, raw := f.list(t, f.d.adminTok, f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, core.BreakGlassListScopeProject, out.Data.Scope, raw)
	assert.Equal(t, sortedUints(f.aliceP, f.aliceRev, f.aliceExpired, f.bobP, f.bobExp), bgIDs(out), raw)
	assert.Equal(t, 5, out.Data.Count, raw)

	// A project_admin of P (roles.read at P only) sees the whole of P.
	ctx := context.Background()
	pa, err := f.d.c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "pam", Email: "pam@keyorix.demo", DisplayName: "Pam Admin", Password: shareDemoPassword,
	})
	require.NoError(t, err)
	require.NoError(t, f.d.c.AddProjectMember(ctx, f.d.adminID, f.d.projectID, pa.ID, "project_admin", false))
	sess, _, err := f.d.c.Login(ctx, &core.LoginRequest{Username: "pam", Password: shareDemoPassword})
	require.NoError(t, err)
	code, out, raw = f.list(t, sess.SessionToken, f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, core.BreakGlassListScopeProject, out.Data.Scope, raw)
	assert.Len(t, out.Data.Activations, 5, raw)
	// ...and nothing at payments, where she is not a member: refused, as before.
	code, _, raw = f.list(t, sess.SessionToken, f.paymentsID)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)
}

// Cross-project: a member's own view of P never includes their activations elsewhere,
// and a non-member gets the old 403 for every project id, existing or not, so they
// learn nothing, not even existence.
func TestBreakGlassOwnList_CrossProjectAndOutsiders(t *testing.T) {
	f := newBGOwnFixture(t)

	code, out, raw := f.list(t, f.aliceTok, f.paymentsID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.alicePayments}, bgIDs(out), raw)
	code, out, raw = f.list(t, f.aliceTok, f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.NotContains(t, bgIDs(out), f.alicePayments, raw)

	// bob is not a member of payments: refused, alice's activation there unseen.
	code, _, raw = f.list(t, f.bobTok, f.paymentsID)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)

	// oscar holds nothing anywhere: the existing project with five activations and a
	// project that does not exist answer the same.
	code, _, rawP := f.list(t, f.oscarTok, f.d.projectID)
	assert.Equal(t, http.StatusForbidden, code, rawP)
	code, _, rawNone := f.list(t, f.oscarTok, 987654)
	assert.Equal(t, http.StatusForbidden, code, rawNone)
	assert.JSONEq(t, rawNone, rawP, "an outsider must not tell a populated project from a missing one")
	assert.NotContains(t, rawP, bgOwnJustificationPrefix, rawP)
}

// Machine identities behave as today: roles.read → whole project; without → 403.
func TestBreakGlassOwnList_MachinePrincipalUnchanged(t *testing.T) {
	f := newBGOwnFixture(t)
	ctx := context.Background()
	c := f.d.c
	roleID := func(name string) uint {
		r, err := c.Storage().GetRoleByName(ctx, name)
		require.NoError(t, err)
		return r.ID
	}
	machine := func(name, role string) string {
		mi, err := c.CreateMachineIdentity(ctx, f.d.projectID, name, "ci", "", "", f.d.adminID, 0)
		require.NoError(t, err)
		require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID(role), core.Scope{ProjectID: f.d.projectID}, f.d.adminID, false))
		tok, err := c.IssueMachineToken(ctx, f.d.projectID, mi.ID, f.d.adminID, core.IssueMachineTokenParams{Name: name + "-token"})
		require.NoError(t, err)
		return tok.PlainToken
	}

	code, _, raw := f.list(t, machine("bg-viewer-bot", "project_viewer"), f.d.projectID)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)
	assert.NotContains(t, raw, "activations", raw)

	// project_admin holds roles.read at P: the whole project, as today.
	code, out, raw := f.list(t, machine("bg-admin-bot", "project_admin"), f.d.projectID)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, core.BreakGlassListScopeProject, out.Data.Scope, raw)
	assert.Len(t, out.Data.Activations, 5, raw)
}

// A PAT restriction (ADR-042) bounds the own view like it bounded the old gate.
func TestBreakGlassOwnList_PATRestriction(t *testing.T) {
	f := newBGOwnFixture(t)
	ctx := context.Background()
	mint := func(scopes []string, projectID uint) string {
		res, err := f.d.c.CreateOwnPAT(ctx, f.d.aliceID, fmt.Sprintf("bg-own-%v-%d", scopes, projectID), nil, scopes, projectID, 0, nil)
		require.NoError(t, err)
		return res.PlainToken
	}

	for name, tc := range map[string]struct {
		tok  string
		want int
	}{
		"unrestricted":            {mint(nil, 0), http.StatusOK},
		"confined_to_P":           {mint(nil, f.d.projectID), http.StatusOK},
		"roles_read_only":         {mint([]string{"roles.read"}, 0), http.StatusOK},
		"confined_to_payments":    {mint(nil, f.paymentsID), http.StatusForbidden},
		"secrets_read_only":       {mint([]string{"secrets.read"}, 0), http.StatusForbidden},
		"secrets_read_confined_P": {mint([]string{"secrets.read"}, f.d.projectID), http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, raw := f.list(t, tc.tok, f.d.projectID)
			require.Equal(t, tc.want, code, raw)
			if tc.want == http.StatusOK {
				assert.Equal(t, core.BreakGlassListScopeOwn, out.Data.Scope, raw)
				assert.Equal(t, sortedUints(f.aliceP, f.aliceRev, f.aliceExpired), bgIDs(out), raw)
				return
			}
			assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)
		})
	}
}

// The per-project MFA policy (ADR-037) still applies to the own view, as it did at
// the route gate: a session without a second factor is refused on an MFA project.
func TestBreakGlassOwnList_ProjectMFAPolicyApplies(t *testing.T) {
	f := newBGOwnFixture(t)
	requireMFA := true
	_, err := f.d.c.UpdateProject(context.Background(), f.d.projectID, "backend-api", "Backend API", &requireMFA)
	require.NoError(t, err)

	code, _, raw := f.list(t, f.aliceTok, f.d.projectID)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.Contains(t, raw, "ProjectMFARequired", raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)

	// payments does not require MFA: alice's own view there is unaffected.
	code, _, raw = f.list(t, f.aliceTok, f.paymentsID)
	assert.Equal(t, http.StatusOK, code, raw)

	// A non-member must not learn that P exists and requires MFA: they get the same
	// generic 403 as for a project that does not exist, never ProjectMFARequired.
	code, _, rawP := f.list(t, f.oscarTok, f.d.projectID)
	assert.Equal(t, http.StatusForbidden, code, rawP)
	assert.NotContains(t, rawP, "ProjectMFARequired", rawP)
	_, _, rawNone := f.list(t, f.oscarTok, 987654)
	assert.JSONEq(t, rawNone, rawP, "an outsider must not tell an MFA project from a missing one")
}

// Listing writes no audit event, for either view: it never did.
func TestBreakGlassOwnList_NotAudited(t *testing.T) {
	f := newBGOwnFixture(t)
	ctx := context.Background()
	count := func() int64 {
		_, total, err := f.d.c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Page: 1, PageSize: 1})
		require.NoError(t, err)
		return total
	}
	before := count()
	for _, tok := range []string{f.aliceTok, f.d.adminTok} {
		code, _, raw := f.list(t, tok, f.d.projectID)
		require.Equal(t, http.StatusOK, code, raw)
	}
	assert.Equal(t, before, count(), "listing break-glass activations must stay unaudited, as before")
}

// Andrei 2026-10-13 (FIX-3184): the own view shows status, timestamps, reason,
// expiry and whether the activation was reviewed / revoked, but NOT the reviewer's
// note, the reviewer's id or the revoker's id. Callers with roles.read still get
// them. The keys are checked on the raw JSON object, so "omitted" means absent,
// not an empty placeholder.
func TestBreakGlassOwnList_OwnViewOmitsReviewNoteAndAdminIdentities(t *testing.T) {
	f := newBGOwnFixture(t)
	const note = "FIX-3184 confidential reviewer note"

	// The admin (not the activator) reviews alice's revoked activation.
	code, raw := doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/review", f.d.projectID, f.aliceRev),
		[]byte(fmt.Sprintf(`{"note":%q}`, note)))
	require.Equal(t, http.StatusOK, code, raw)

	row := func(tok string) (map[string]any, string) {
		t.Helper()
		code, raw := doMachineRequest(t, f.d.srv, tok, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/break-glass", f.d.projectID), nil)
		require.Equal(t, http.StatusOK, code, raw)
		var out struct {
			Data struct {
				Activations []map[string]any `json:"activations"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		for _, a := range out.Data.Activations {
			if uint(a["id"].(float64)) == f.aliceRev {
				return a, raw
			}
		}
		t.Fatalf("activation %d missing: %s", f.aliceRev, raw)
		return nil, raw
	}

	own, ownRaw := row(f.aliceTok)
	for _, k := range []string{"review_note", "reviewed_by", "revoked_by", "revoked_by_machine_identity_id"} {
		assert.NotContains(t, own, k, ownRaw)
	}
	assert.NotContains(t, ownRaw, note, ownRaw)
	for _, k := range []string{"state", "created_at", "expires_at", "justification", "revoked_at", "reviewed_at"} {
		assert.Contains(t, own, k, ownRaw)
	}
	assert.Equal(t, "revoked", own["state"], ownRaw)

	// roles.read: unchanged.
	full, fullRaw := row(f.d.adminTok)
	assert.Equal(t, note, full["review_note"], fullRaw)
	assert.Equal(t, float64(f.d.adminID), full["reviewed_by"], fullRaw)
	assert.Equal(t, float64(f.d.adminID), full["revoked_by"], fullRaw)
	assert.Contains(t, full, "reviewed_at", fullRaw)
	assert.Contains(t, full, "revoked_at", fullRaw)
}
