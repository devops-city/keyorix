package http

// revocation_after_commit_test.go — PERF-CRED-LOOKUP-1 item 4.
//
// The property every credential cache must keep: once the call that ends a
// credential has returned (its commit is done), NO replica authenticates that
// credential again, on any transport. Ended means revoked, rotated away,
// expired, its owner suspended or deleted, its machine identity suspended or
// revoked, or (sessions) logged out, revoked or rotated.
//
// Replica B holds a warm auth-cache entry for the credential (the middleware's
// token cache, re-checked live on every hit: INV-MW-02). Replica A ends the
// credential through core with no cache invalidator wired, so nothing evicts
// B's entry: B stands in for every replica that did not run the change, and its
// own live re-check is the only thing that can refuse. Every request on B after
// A's call returned must be refused exactly as an unknown token of the same
// kind is (REST), or refused without a value (gRPC, which has no auth cache).
//
// Each case runs twice per backend, once with the folded secret read
// (GET /api/v1/secrets/{id}, the credential re-check that also reads the node)
// as the first request after the change and once with the by-ref read (the
// plain credential statement): only the first request after the change is a
// cache hit, the deny evicts the entry.
//
// TestRevocationAfterCommit_AuditRefused_EveryCredentialType runs the same
// cases with the audit log refusing every write from just before the change:
// a revocation is never blocked or delayed by the audit log (Andrei
// 2026-10-14, INV-CORE-security-mutation-audit-same-tx's "Revocations are
// deliberately NOT covered"). Rotation with ReplaceCredentialID is left out
// there on purpose: it is a credential issue (grant-shaped, fail-closed on the
// audit, AUDIT-TX-2) and its revoke of the old credential shares that
// transaction, so with the audit refused the rotation is refused as a whole and
// the old credential is still live; the plain revoke is the control that is
// never audit-gated.
//
// Not covered here: federated OIDC principals (no issuer harness in this
// package; their cache-hit re-check, CurrentFederatedMachineState, is pinned in
// server/middleware cache_hit_fail_closed_test.go), and node/role/schedule
// changes on the folded path (TestFoldedCredential_CrossReplicaInvalidation).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// racCred is the credential one case ends.
type racCred struct {
	kind              string // "machine" | "pat" | "session"
	token             string
	userID, patID     uint
	machineID, credID uint
}

type racCase struct {
	kind, name string
	// auditGated: the change is refused while the audit log refuses (only
	// rotation, see the file header).
	auditGated bool
	end        func(t *testing.T, w *svWorld, c racCred) error
}

const racPassword = "Rac#Pass-4x9!Lw-Qz7$"

func racCases() []racCase {
	ctx := context.Background()
	past := func() time.Time { return time.Now().UTC().Add(-time.Minute) }
	return []racCase{
		{kind: "machine", name: "credential-revoked", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.RevokeMachineToken(ctx, w.projID, c.machineID, c.credID, w.adminID)
			return err
		}},
		{kind: "machine", name: "credential-rotated", auditGated: true, end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.IssueMachineToken(ctx, w.projID, c.machineID, w.adminID, core.IssueMachineTokenParams{Name: "rac-rotated", ReplaceCredentialID: c.credID})
			return err
		}},
		{kind: "machine", name: "credential-expired", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.db.Model(&models.MachineIdentityCredential{}).Where("id = ?", c.credID).Update("expires_at", past()).Error
		}},
		{kind: "machine", name: "identity-suspended", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.TransitionMachineIdentity(ctx, w.projID, c.machineID, core.MachineSuspended, w.adminID)
			return err
		}},
		{kind: "machine", name: "identity-revoked", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.TransitionMachineIdentity(ctx, w.projID, c.machineID, core.MachineRevoked, w.adminID)
			return err
		}},
		{kind: "pat", name: "pat-revoked", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.RevokeOwnPAT(ctx, c.userID, c.patID)
			return err
		}},
		{kind: "pat", name: "pat-expired", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.db.Model(&models.PersonalAccessToken{}).Where("id = ?", c.patID).Update("expires_at", past()).Error
		}},
		{kind: "pat", name: "owner-suspended", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.c.SuspendUser(ctx, w.adminID, c.userID)
		}},
		{kind: "pat", name: "owner-deleted", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.c.DeleteUser(ctx, w.adminID, c.userID)
		}},
		{kind: "session", name: "logged-out", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.c.Logout(ctx, c.token)
		}},
		{kind: "session", name: "sessions-revoked", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.RevokeUserSessions(ctx, w.adminID, c.userID)
			return err
		}},
		{kind: "session", name: "session-rotated", end: func(_ *testing.T, w *svWorld, c racCred) error {
			_, err := w.a.c.RefreshSession(ctx, c.token)
			return err
		}},
		{kind: "session", name: "session-expired", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.db.Model(&models.Session{}).Where("user_id = ?", c.userID).Update("expires_at", past()).Error
		}},
		{kind: "session", name: "owner-suspended", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.c.SuspendUser(ctx, w.adminID, c.userID)
		}},
		{kind: "session", name: "owner-deleted", end: func(_ *testing.T, w *svWorld, c racCred) error {
			return w.a.c.DeleteUser(ctx, w.adminID, c.userID)
		}},
	}
}

// racRemoteSeq gives every request sequence its own source address, so the
// per-IP failed-auth budget (recordTokenAuthFailure) spent by the unknown-token
// references of one case never turns another case's 401 into a 429.
var racRemoteSeq atomic.Int64

// racREST is one authenticated GET on r: "200" or "status body".
func racREST(r *svReplica, token, url, remote string) string {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		return "200"
	}
	return fmt.Sprintf("%d %s", rec.Code, svNormalizeBody(rec.Body.String()))
}

// racSubject creates the credential of kind on w: a reader user (PAT, session)
// or the world's machine token. The user holds sv-reader on the project, like
// the machine identity.
func racSubject(t *testing.T, w *svWorld, kind string) racCred {
	t.Helper()
	ctx := context.Background()
	if kind == "machine" {
		tok := w.tokens["machine"]
		var cred models.MachineIdentityCredential
		require.NoError(t, w.a.db.Where("token_hash = ?", cgSHA256Hex(tok)).First(&cred).Error)
		return racCred{kind: kind, token: tok, machineID: cred.MachineIdentityID, credID: cred.ID}
	}
	n := w.seq.Add(1)
	u, err := w.a.c.CreateUser(ctx, &core.CreateUserRequest{Username: fmt.Sprintf("racuser%d", n), Email: fmt.Sprintf("racuser%d@x.io", n), Password: racPassword})
	require.NoError(t, err)
	var role models.Role
	require.NoError(t, w.a.db.Where("name = ?", "sv-reader").First(&role).Error)
	require.NoError(t, w.a.c.AssignUserRole(ctx, 0, u.ID, role.ID, core.Scope{ProjectID: w.projID}, false))
	if kind == "pat" {
		pat, err := w.a.c.CreateOwnPAT(ctx, u.ID, "rac", nil, nil, 0, 0, nil)
		require.NoError(t, err)
		return racCred{kind: kind, token: pat.PlainToken, userID: u.ID, patID: pat.Token.ID}
	}
	sess, _, err := w.a.c.Login(ctx, &core.LoginRequest{Username: u.Username, Password: racPassword})
	require.NoError(t, err)
	return racCred{kind: kind, token: sess.SessionToken, userID: u.ID}
}

// racUnknownToken is a well-formed token of kind that matches no credential.
func racUnknownToken(kind string, n int64) string {
	switch kind {
	case "machine":
		return fmt.Sprintf("kx_machine_%064d", n)
	case "pat":
		return fmt.Sprintf("kx_pat_%064d", n)
	}
	return fmt.Sprintf("rac-unknown-session-%064d", n)
}

// racRun warms B, ends the credential through A, and asserts B refuses it on
// every transport from the first request on. firstRoute is the REST route
// whose request is the cache hit.
func racRun(t *testing.T, backend string, tc racCase, firstRoute string, refuseAudit bool) {
	t.Helper()
	w := newSVWorld(t, backend, 2)
	sec, val := w.newSecret(t, nil)
	cred := racSubject(t, w, tc.kind)
	w.tokens["subject"] = cred.token
	routes := map[string]string{
		"folded": fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec.ID),
		"by-ref": "/api/v1/secrets/value?ref=svproj/prod/" + sec.Name,
	}
	order := []string{"folded", "by-ref"}
	if firstRoute == "by-ref" {
		order = []string{"by-ref", "folded"}
	}
	remote := fmt.Sprintf("198.18.%d.%d:4000", racRemoteSeq.Add(1)%250, racRemoteSeq.Load()%250+1)

	for _, rt := range order {
		require.Equal(t, "200", racREST(w.b, cred.token, routes[rt], remote), "precondition: %s authenticates on B (%s)", tc.kind, rt)
	}
	require.Equal(t, "200", racREST(w.b, cred.token, routes[order[0]], remote), "precondition: B serves the cache hit")
	require.Equal(t, val, w.read(t, w.b, "grpc", "subject", sec).Value, "precondition: gRPC on B")

	if refuseAudit {
		// From here every audit write on every replica fails (shared database).
		require.NoError(t, w.a.db.Exec("ALTER TABLE audit_events RENAME TO audit_events_refused_rac").Error)
	}
	err := tc.end(t, w, cred)
	if refuseAudit && tc.auditGated {
		require.Error(t, err, "%s is audit-gated (see the file header)", tc.name)
		// TODAY's behaviour: the refused rotation rolls back as a whole, so the OLD
		// credential is still live, on replica B too (its warm cache entry included),
		// on both REST routes and on gRPC.
		// MERGE-FIX-3482G (Andrei 2026-10-20, ask perf-cred-lookup-1-rotation-audit-gated
		// = b) splits rotation: revoking the old credential becomes owed and is no
		// longer audit-gated, issuing the new one stays fail closed. Its one-line
		// change here: make the old token refused like an unknown token (the
		// assertion every non-gated case below ends with) instead of "200".
		//
		// The audit log is given back first: a secret READ is itself audit-gated
		// (secret.read fails closed while the audit refuses), so with the table still
		// renamed no read could tell a live credential from a revoked one.
		require.NoError(t, w.a.db.Exec("ALTER TABLE audit_events_refused_rac RENAME TO audit_events").Error)
		for _, rt := range order {
			require.Equal(t, "200", racREST(w.b, cred.token, routes[rt], remote),
				"old %s credential must still authenticate on B after the audit-refused %s (%s route)", tc.kind, tc.name, rt)
		}
		require.Equal(t, val, w.read(t, w.b, "grpc", "subject", sec).Value,
			"old %s credential must still authenticate over gRPC on B after the audit-refused %s", tc.kind, tc.name)
		return
	}
	require.NoError(t, err, "ending the credential (%s) must succeed%s", tc.name, map[bool]string{true: " while the audit log refuses", false: ""}[refuseAudit])

	unknown := racREST(w.b, racUnknownToken(tc.kind, w.seq.Add(1)), routes[order[0]], remote)
	require.Contains(t, unknown, "401", "reference: an unknown %s token", tc.kind)
	for i, rt := range order {
		require.Equal(t, unknown, racREST(w.b, cred.token, routes[rt], remote),
			"request %d on B after %s committed on A (%s route) must be refused exactly like an unknown token", i+1, tc.name, rt)
	}
	got := w.read(t, w.b, "grpc", "subject", sec)
	require.Empty(t, got.Value, "gRPC on B after %s committed on A must disclose nothing: %s", tc.name, got)
	require.Equal(t, int(codes.Unauthenticated), got.Status,
		"gRPC on B after %s committed on A must be refused as unauthenticated (not rate limited): %s", tc.name, got)
}

// TestRevocationAfterCommit_EveryCredentialType: see the file header.
func TestRevocationAfterCommit_EveryCredentialType(t *testing.T) {
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range racCases() {
			for _, first := range []string{"folded", "by-ref"} {
				t.Run(tc.kind+"/"+tc.name+"/"+first+"-first", func(t *testing.T) {
					racRun(t, backend, tc, first, false)
				})
			}
		}
	})
}

// TestRevocationAfterCommit_AuditRefused_EveryCredentialType: the same, with
// the audit log refusing every write from just before the change.
func TestRevocationAfterCommit_AuditRefused_EveryCredentialType(t *testing.T) {
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range racCases() {
			t.Run(tc.kind+"/"+tc.name, func(t *testing.T) {
				racRun(t, backend, tc, "folded", true)
			})
		}
	})
}
