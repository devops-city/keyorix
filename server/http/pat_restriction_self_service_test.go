// pat_restriction_self_service_test.go — PAT-GUARD-2: the two ungated
// self-service writes #3062 reviewed and left open, decided by Andrei on
// 2026-10-11 (ADR-042, "Addendum (2026-10-11): self-service writes"):
//
//   - POST /api/v1/projects/{id}/break-glass is REFUSED for a restricted PAT. It is
//     not RBAC-gated, so Authorize never sees it, and it grants the owner an
//     emergency role: a privilege-escalation path a token confined below its owner
//     must not reach. Same refusal shape as POST /auth/tokens
//     (ErrRestrictedPATCannotMintPAT): 403, nothing created.
//   - DELETE /api/v1/auth/tokens/{id} and DELETE /api/v1/auth/sessions/{id} stay
//     ALLOWED for a restricted PAT, for the owner's OWN tokens and sessions only.
//     Revoking only reduces access, and a leaked restricted token's owner must be
//     able to kill credentials with whatever token they still hold.
//
// The fixture is #3062's newPATGuardWorld (two owners, five restricted personas
// each, unrestricted controls). gRPC has no own-token/session revoke RPC; its
// break-glass half is in server/grpc/pat_restriction_self_service_test.go.
package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// patGuardOwners are newPATGuardWorld's two PAT owners: token-map prefix and
// username.
var patGuardOwners = []struct{ prefix, username string }{{"", "pgowner"}, {"admin_", "testadmin"}}

// TestPATRestriction_RestrictedPATCannotActivateBreakGlass: every restricted
// persona of both owners is refused with 403 and creates no activation; the same
// owners' unrestricted PATs then activate successfully, so the refusal is the
// restriction and not a fixture that could never succeed.
func TestPATRestriction_RestrictedPATCannotActivateBreakGlass(t *testing.T) {
	w := newPATGuardWorld(t)
	ctx := context.Background()
	// project_developer: a contained project role neither owner holds (both are
	// project_admin at the canary project), so a real activation can succeed.
	w.core.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
	path := fmt.Sprintf("/api/v1/projects/%d/break-glass", w.canaryPID)
	body := []byte(`{"justification":"PAT-GUARD-2 incident response drill"}`)

	for _, o := range patGuardOwners {
		for _, persona := range patGuardRestrictedPersonas {
			t.Run(o.prefix+persona, func(t *testing.T) {
				code, resp := w.do(t, http.MethodPost, w.tokens[o.prefix+persona], path, body)
				assert.Equal(t, http.StatusForbidden, code, resp)
				assert.Contains(t, resp, core.ErrRestrictedPATCannotBreakGlass.Error())
			})
		}
	}
	activations, err := w.core.ListBreakGlassActivations(ctx, w.canaryPID)
	require.NoError(t, err)
	require.Empty(t, activations, "a refused activation must not grant anything")

	for _, o := range patGuardOwners {
		t.Run("control_"+o.prefix+"pat_unrestricted", func(t *testing.T) {
			code, resp := w.do(t, http.MethodPost, w.tokens[o.prefix+"pat_unrestricted"], path, body)
			assert.Equal(t, http.StatusCreated, code, resp)
		})
	}
	activations, err = w.core.ListBreakGlassActivations(ctx, w.canaryPID)
	require.NoError(t, err)
	assert.Len(t, activations, len(patGuardOwners), "the unrestricted controls must activate")
}

// TestPATRestriction_RestrictedPATRevokesOnlyOwnTokensAndSessions: every
// restricted persona revokes a fresh PAT and a fresh session of its OWN owner (204,
// and the revoked credential stops authenticating), and gets 404 for the other
// owner's PAT and session, which keep working.
func TestPATRestriction_RestrictedPATRevokesOnlyOwnTokensAndSessions(t *testing.T) {
	w := newPATGuardWorld(t)
	ctx := context.Background()
	passwords := map[string]string{"pgowner": membershipsGatePassword, "testadmin": "TestPassword123!"}

	type cred struct {
		patID, sessionID uint
		pat, session     string
	}
	fresh := func(t *testing.T, username, name string) cred {
		t.Helper()
		u, err := w.core.GetUserByEmail(ctx, username+"@example.com")
		require.NoError(t, err)
		p, err := w.core.CreateOwnPAT(ctx, u.ID, name, nil, nil, 0, 0, nil)
		require.NoError(t, err)
		s, _, err := w.core.Login(ctx, &core.LoginRequest{Username: username, Password: passwords[username]})
		require.NoError(t, err)
		return cred{patID: p.Token.ID, sessionID: s.ID, pat: p.PlainToken, session: s.SessionToken}
	}
	alive := func(t *testing.T, token string) bool {
		t.Helper()
		code, _ := w.get(t, token, "/api/v1/auth/tokens")
		return code == http.StatusOK
	}

	for i, o := range patGuardOwners {
		other := patGuardOwners[1-i]
		for _, persona := range patGuardRestrictedPersonas {
			t.Run(o.prefix+persona, func(t *testing.T) {
				caller := w.tokens[o.prefix+persona]
				mine := fresh(t, o.username, "own-"+persona)
				theirs := fresh(t, other.username, "other-"+persona)
				require.True(t, alive(t, mine.pat) && alive(t, mine.session) && alive(t, theirs.pat) && alive(t, theirs.session),
					"fixture: every fresh credential authenticates before the revokes")

				code, resp := w.do(t, http.MethodDelete, caller, fmt.Sprintf("/api/v1/auth/tokens/%d", theirs.patID), nil)
				assert.Equal(t, http.StatusNotFound, code, resp)
				code, resp = w.do(t, http.MethodDelete, caller, fmt.Sprintf("/api/v1/auth/sessions/%d", theirs.sessionID), nil)
				assert.Equal(t, http.StatusNotFound, code, resp)
				assert.True(t, alive(t, theirs.pat), "another user's PAT must survive")
				assert.True(t, alive(t, theirs.session), "another user's session must survive")

				code, resp = w.do(t, http.MethodDelete, caller, fmt.Sprintf("/api/v1/auth/tokens/%d", mine.patID), nil)
				assert.Equal(t, http.StatusNoContent, code, resp)
				code, resp = w.do(t, http.MethodDelete, caller, fmt.Sprintf("/api/v1/auth/sessions/%d", mine.sessionID), nil)
				assert.Equal(t, http.StatusNoContent, code, resp)
				assert.False(t, alive(t, mine.pat), "the owner's revoked PAT must stop authenticating")
				assert.False(t, alive(t, mine.session), "the owner's revoked session must stop authenticating")
			})
		}
	}
}
