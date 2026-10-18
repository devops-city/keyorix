package grpc_test

// authz_walk_dead_credential_test.go — AUTHZ-WALKS-GRPC-1 item 2
// (INV-GRPC-dead-credential-walk).
//
// Every registered RPC (unary and streaming, read from GetServiceInfo) is called
// with a credential in each DEAD state, and must answer the state's contract
// code with no state change:
//
//	session   logged out (revoked) | idle-expired | absolute-expired
//	user      suspended | deleted | deactivated — each both through the core API
//	          (which also revokes credentials) and as a bare state flip with the
//	          credential left intact, so the account check is proven on its own
//	PAT       revoked | expired | owner suspended | owner deleted
//	machine   identity revoked | identity suspended | token revoked | token expired
//
// Every credential belongs to a principal that WOULD be allowed (project_admin
// on the canary project; project_developer for a machine), so an accepted dead
// credential shows up as an OK, a canary leak or a state change, not as a
// denial that happens to look right.
//
// Cold vs warm: gRPC has no auth cache of its own (interceptors/auth.go), but the
// core keeps per-request lookups, and a bearer that has authenticated before is
// the shape a stale-cache bug needs. A WARM credential is used for one
// successful call before it dies; a COLD one never authenticated.
//
// Oracle per call: Unauthenticated (the contract code for every state today —
// the table in deadStates names it per state, so a state with a different
// contract is a deliberate edit), except for the pinned public methods, which
// never look at the credential; no canary data in the response; the digest of
// every table is unchanged; no audit row is appended.
//
// Each call uses its own connection (hence its own fake peer IP) because the
// gRPC invalid-token limiter is process-global and allows 10 failures per IP;
// see uniquePeerListener.
//
// What this does NOT cover: the HTTP bearer cache (this transport has none);
// credentials whose state changes DURING a long-lived stream (INV-GRPC re-auth
// on streams); other transports' revocation paths.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

type deadCred struct {
	token     string
	userID    uint
	machineID uint
	credID    uint // PAT id or machine-token credential id
}

type deadState struct {
	name string
	kind string // "session" | "pat" | "machine"
	// patExpiry: issue the credential with a future expiry the kill step then rewinds.
	expiring bool
	kill     func(t *testing.T, w *walkWorld, c *deadCred)
	// want is the contract status code for a call made with the dead credential.
	want codes.Code
	// sideEffectTables are the only tables a call with this dead credential may
	// change, with the documented reason. Empty for every state but one.
	sideEffectTables map[string]string
}

func pastTime() time.Time { return time.Now().Add(-time.Hour).UTC() }

func mustUpdate(t *testing.T, w *walkWorld, model any, col string, val any, where string, arg any) {
	t.Helper()
	res := w.db.Model(model).Where(where, arg).Update(col, val)
	require.NoError(t, res.Error)
	require.NotZerof(t, res.RowsAffected, "updating %s on %T matched no row", col, model)
}

var deadStates = []deadState{
	{name: "session-logged-out", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.core.Logout(context.Background(), c.token))
		}},
	{name: "session-idle-expired", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.Session{}, "expires_at", pastTime(), "user_id = ?", c.userID)
		}},
	{name: "session-absolute-expired", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.Session{}, "absolute_expires_at", pastTime(), "user_id = ?", c.userID)
		}},
	{name: "session-user-suspended-api", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.core.SuspendUser(context.Background(), w.adminID, c.userID))
		}},
	{name: "session-user-suspended-state-only", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.User{}, "account_state", core.AccountSuspended, "id = ?", c.userID)
		}},
	{name: "session-user-deleted-api", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.core.DeleteUser(context.Background(), w.adminID, c.userID))
		}},
	{name: "session-user-deleted-state-only", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.db.Delete(&models.User{}, c.userID).Error)
		}},
	{name: "session-user-deactivated-state-only", kind: "session", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.User{}, "is_active", false, "id = ?", c.userID)
		}},
	{name: "pat-revoked", kind: "pat", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			_, err := w.core.RevokeOwnPAT(context.Background(), c.userID, c.credID)
			require.NoError(t, err)
		}},
	// Presenting an EXPIRED PAT notifies its owner, once (core.ValidatePATToken ->
	// emitPATExpiredNotification, deduplicated): a documented, owner-directed
	// notification, not an effect of the rejected request on anything it asked for.
	{name: "pat-expired", kind: "pat", expiring: true, want: codes.Unauthenticated,
		sideEffectTables: map[string]string{"notifications": "owner is told an expired PAT was presented (emitPATExpiredNotification)"},
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.PersonalAccessToken{}, "expires_at", pastTime(), "id = ?", c.credID)
		}},
	{name: "pat-owner-suspended-api", kind: "pat", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.core.SuspendUser(context.Background(), w.adminID, c.userID))
		}},
	{name: "pat-owner-suspended-state-only", kind: "pat", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.User{}, "account_state", core.AccountSuspended, "id = ?", c.userID)
		}},
	{name: "pat-owner-deleted-state-only", kind: "pat", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			require.NoError(t, w.db.Delete(&models.User{}, c.userID).Error)
		}},
	{name: "machine-identity-revoked", kind: "machine", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			_, err := w.core.TransitionMachineIdentity(context.Background(), w.ids.canaryProject, c.machineID, core.MachineRevoked, w.adminID)
			require.NoError(t, err)
		}},
	{name: "machine-identity-suspended", kind: "machine", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			_, err := w.core.TransitionMachineIdentity(context.Background(), w.ids.canaryProject, c.machineID, core.MachineSuspended, w.adminID)
			require.NoError(t, err)
		}},
	{name: "machine-token-revoked", kind: "machine", want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			_, err := w.core.RevokeMachineToken(context.Background(), w.ids.canaryProject, c.machineID, c.credID, w.adminID)
			require.NoError(t, err)
		}},
	{name: "machine-token-expired", kind: "machine", expiring: true, want: codes.Unauthenticated,
		kill: func(t *testing.T, w *walkWorld, c *deadCred) {
			mustUpdate(t, w, &models.MachineIdentityCredential{}, "expires_at", pastTime(), "id = ?", c.credID)
		}},
}

var deadSeq int

// newDeadCred mints a LIVE credential of st's kind for a principal that would be
// allowed to read and write the canary project.
func newDeadCred(t *testing.T, w *walkWorld, st deadState) *deadCred {
	t.Helper()
	ctx := context.Background()
	c := w.core
	deadSeq++
	name := fmt.Sprintf("walkdead%d", deadSeq)
	cred := &deadCred{}
	var expiry *time.Time
	if st.expiring {
		e := time.Now().Add(time.Hour).UTC()
		expiry = &e
	}
	if st.kind == "machine" {
		mi, err := c.CreateMachineIdentity(ctx, w.ids.canaryProject, name, "ci", "", "", w.adminID, 0)
		require.NoError(t, err)
		role, err := w.storageRole(t, "project_developer")
		require.NoError(t, err)
		require.NoError(t, c.AssignMachineRole(ctx, mi.ID, role, core.Scope{ProjectID: w.ids.canaryProject}, w.adminID, false))
		tok, err := c.IssueMachineToken(ctx, w.ids.canaryProject, mi.ID, w.adminID, core.IssueMachineTokenParams{Name: name, ExpiresAt: expiry})
		require.NoError(t, err)
		cred.token, cred.machineID, cred.credID = tok.PlainToken, mi.ID, tok.Credential.ID
		return cred
	}
	u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: walkPassword})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, w.adminID, w.ids.canaryProject, u.ID, "project_admin", false))
	cred.userID = u.ID
	if st.kind == "pat" {
		pat, err := c.CreateOwnPAT(ctx, u.ID, name, expiry, nil, 0, 0, nil)
		require.NoError(t, err)
		cred.token, cred.credID = pat.PlainToken, pat.Token.ID
		return cred
	}
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: name, Password: walkPassword})
	require.NoError(t, err)
	cred.token = sess.SessionToken
	return cred
}

func (w *walkWorld) storageRole(t *testing.T, name string) (uint, error) {
	t.Helper()
	roles, err := w.core.Storage().ListRoles(context.Background())
	if err != nil {
		return 0, err
	}
	for _, r := range roles {
		if r.Name == name {
			return r.ID, nil
		}
	}
	return 0, fmt.Errorf("built-in role %q not found", name)
}

func (w *walkWorld) method(t *testing.T, key string) walkMethod {
	t.Helper()
	for _, m := range w.methods {
		if m.key() == key {
			return m
		}
	}
	t.Fatalf("method %s is not registered", key)
	return walkMethod{}
}

func TestEveryGRPCMethodRejectsDeadCredential(t *testing.T) {
	forEachWalkBackend(t, func(t *testing.T, w *walkWorld) {
		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}
		publicKeys := map[string]bool{}
		for full := range expectedPublicGRPCMethods {
			publicKeys[strings.TrimPrefix(full, "/")] = true
		}
		warmMethod := w.method(t, "keyorix.v1.ProjectService/ListProjects")

		violations := map[string]bool{}
		calls := 0
		for _, st := range deadStates {
			for _, warm := range []bool{false, true} {
				temp := "cold"
				if warm {
					temp = "warm"
				}
				label := st.name + "/" + temp
				cred := newDeadCred(t, w, st)
				if warm {
					// The credential is live and has authenticated once: prove it, so
					// "warm" means what it says and the kill step is what changes it.
					conn := w.dial(t)
					res := call(t, conn, warmMethod, cred.token, requestFor(warmMethod.input, w.ids.variants()[0].bind))
					_ = conn.Close()
					require.NoErrorf(t, res.err, "%s: the credential was not live before it was killed", label)
				}
				st.kill(t, w, cred)

				drain()
				before := w.digest(t)
				for _, m := range w.methods {
					conn := w.dial(t)
					res := call(t, conn, m, cred.token, requestFor(m.input, w.ids.variants()[0].bind))
					_ = conn.Close()
					drain()
					after := w.digest(t)
					calls++

					var why []string
					got := status.Code(res.err)
					switch {
					case publicKeys[m.key()]:
						if got != codes.OK {
							why = append(why, fmt.Sprintf("public method answered %s", got))
						}
					case got != st.want:
						why = append(why, fmt.Sprintf("answered %s %q, contract is %s", got, status.Convert(res.err).Message(), st.want))
					}
					if res.leaksCanary() {
						why = append(why, "response carries canary data")
					}
					var unexplained []string
					for _, tbl := range before.changedTables(after) {
						if _, ok := st.sideEffectTables[tbl]; !ok {
							unexplained = append(unexplained, tbl)
						}
					}
					if len(unexplained) > 0 {
						why = append(why, fmt.Sprintf("state changed (%s)", strings.Join(unexplained, ",")))
					}
					if d := before.auditDelta(after); len(d) > 0 {
						why = append(why, fmt.Sprintf("audit rows appended %v", d))
					}
					if len(why) > 0 {
						violations[fmt.Sprintf("%s %s: %s", label, m.key(), strings.Join(why, "; "))] = true
					}
					before = after
				}
			}
		}
		t.Logf("[%s] dead-credential walk: %d states x cold/warm x %d methods = %d calls", w.backend, len(deadStates), len(w.methods), calls)

		out := make([]string, 0, len(violations))
		for v := range violations {
			out = append(out, v)
		}
		sort.Strings(out)
		for _, v := range out {
			t.Errorf("DEAD CREDENTIAL WALK VIOLATION %s", v)
		}
	})
}
