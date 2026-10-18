// dead_credentials_walk_test.go — AUTHZ-WALKS-HTTP-1 item 2: no route serves a
// credential that has died, whether or not the auth cache holds it.
//
// # The class
//
// credential_gone_cache_hit_test.go found that a vanished PAT/machine credential row
// was read as "lookup failed, can't tell" and served from the auth cache until the
// entry expired. That test pins one route (GET /secrets/{id}) per credential end.
// The cache-hit path is shared by every route, so the question "does ANY route still
// answer a dead credential" is a route-wide one.
//
// # The walk: TestEveryRouteRefusesADeadCredential
//
// Behavioural, over the real router (fixture and skipped shapes:
// authz_walk_fixture_test.go). Two replicas share one database. The credential is
// minted and, for the "warm" variant, used once on replica B so B's auth cache holds
// it; it is then ended through replica A (own pool and core, no cache invalidator
// wired, so nothing evicts B's entry: B stands in for every other replica), and the
// ENTIRE route set (every GET and every mutating route, each {param} bound to the
// real canary object of its kind, a union body on writes) is called on B with the dead
// credential. The "cold" variant ends the credential before B ever sees it.
//
// Dead states (awDeadStates): suspended user session; deleted user session; expired
// session; revoked session; revoked PAT; expired PAT; PAT of a suspended user; PAT of a
// deleted user; revoked machine identity; suspended machine identity; machine token of
// a project that was soft-deleted (a machine identity has no delete path of its own;
// its project does).
//
// Oracle, both required, on every request: the status is exactly the state's entry in
// awDeadContract (401 for all of them today), and the digest of every table plus the
// audit event set is unchanged except for denial events. Public routes
// (awPublicRoutes) take no credential and are held to no-5xx and unchanged state;
// POST /auth/logout is additionally 401 for a dead session (INV-HTTP-17).
//
// What it does NOT cover, said plainly: only the first (typed) path per route; one
// union body; credentials killed by means other than the listed ones (a role revoked
// while the credential lives is an authorization change, not a dead credential, and is
// the read/write walks' subject); gRPC; a replica whose cache was filled and then
// evicted through the ADR-039 invalidator (that path is fail-closed by construction).
package http

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// awDeadCred is one minted credential and the way to end it.
type awDeadCred struct {
	token string
	end   func(t *testing.T)
}

type awDeadState struct {
	name string
	// kind: "session" | "pat" | "machine" (decides the logout expectation)
	kind string
	mint func(t *testing.T, w *awWorld, seq int) awDeadCred
}

// awDeadContract: the status every route must answer a credential in that state.
// 401 for all: a dead credential is "not authenticated", the same answer an unknown
// token gets (credential_gone_cache_hit_test.go compares them byte for byte). A state
// that deserves 403 (authenticated but forbidden) would be listed here with a reason;
// none does today.
var awDeadContract = map[string]int{}

// awDeadOpen: states whose current behaviour is NOT the contract and is filed, not
// fixed here. The status check is skipped for them (the no-5xx and unchanged-state
// checks still run) and the walk asserts the credential STILL authenticates, so the
// entry fails the day the issue is fixed and is removed with it.
var awDeadOpen = map[string]string{
	"machine_token_project_deleted": "#3433: a project soft-delete leaves its machine identities and their tokens authenticating (design decision: suspend them or document it)",
}

// awKnownOpenMachineGET: the GET routes #3416 (open) also fixes for a machine token;
// the write walk's awKnownOpen lists the mutating ones. Remove with #3416.
var awKnownOpenMachineGET = map[string]bool{
	"GET /api/v1/auth/sessions": true, "GET /api/v1/auth/tokens": true, "GET /api/v1/auth/tokens/expired": true,
}

// awDeadSideTables: tables a dead-credential request may legitimately add rows to.
var awDeadSideTables = map[string][]string{
	"pat_expired": {"notifications"}, // the owner is told once that an expired token was presented
}

// awDeadLogout: POST /auth/logout is public (it takes a session OR nothing); for the
// listed states it answers this instead of 401. An expired session is time, not an
// event: logout is an idempotent cleanup call and an expired token authenticates
// nothing, so 200 is harmless and changes no state the digest sees. A REVOKED session
// is 401 (INV-HTTP-17).
var awDeadLogout = map[string]int{"session_expired": http.StatusOK}

func awDeadWant(state string) int {
	if c, ok := awDeadContract[state]; ok {
		return c
	}
	return http.StatusUnauthorized
}

func awMintUser(t *testing.T, w *awWorld, seq int, prefix string) (uint, string) {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("%s%d", prefix, seq)
	u, err := w.a.c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@x.io", Password: svPassword})
	require.NoError(t, err)
	// Same standing as the canary viewers: a project member, so a 200 would be a real read.
	require.NoError(t, w.a.c.AddProjectMember(ctx, w.adminID, w.projID, u.ID, "viewer", false))
	sess, _, err := w.a.c.Login(ctx, &core.LoginRequest{Username: name, Password: svPassword})
	require.NoError(t, err)
	return u.ID, sess.SessionToken
}

func awSessionRow(t *testing.T, w *awWorld, userID uint) models.Session {
	t.Helper()
	var s models.Session
	require.NoError(t, w.a.db.Where("user_id = ?", userID).Order("id desc").First(&s).Error)
	return s
}

func awMintPAT(t *testing.T, w *awWorld, userID uint, expires *time.Time) (string, uint) {
	t.Helper()
	res, err := w.a.c.CreateOwnPAT(context.Background(), userID, "aw-dead", expires, nil, 0, 0, nil)
	require.NoError(t, err)
	return res.PlainToken, res.Token.ID
}

var awDeadStates = []awDeadState{
	{"user_suspended_session", "session", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, tok := awMintUser(t, w, seq, "awdsusp")
		return awDeadCred{tok, func(t *testing.T) { require.NoError(t, w.a.c.SuspendUser(context.Background(), w.adminID, uid)) }}
	}},
	{"user_deleted_session", "session", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, tok := awMintUser(t, w, seq, "awddel")
		return awDeadCred{tok, func(t *testing.T) { require.NoError(t, w.a.c.DeleteUser(context.Background(), w.adminID, uid)) }}
	}},
	{"session_expired", "session", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, tok := awMintUser(t, w, seq, "awdexp")
		return awDeadCred{tok, func(t *testing.T) {
			s := awSessionRow(t, w, uid)
			past := time.Now().UTC().Add(-time.Hour)
			require.NoError(t, w.a.db.Model(&models.Session{}).Where("id = ?", s.ID).Update("expires_at", past).Error)
		}}
	}},
	{"session_revoked", "session", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, tok := awMintUser(t, w, seq, "awdrev")
		return awDeadCred{tok, func(t *testing.T) {
			s := awSessionRow(t, w, uid)
			require.NoError(t, w.a.c.RevokeOwnSession(context.Background(), uid, s.ID))
		}}
	}},
	{"pat_revoked", "pat", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, _ := awMintUser(t, w, seq, "awdpatrev")
		tok, id := awMintPAT(t, w, uid, nil)
		return awDeadCred{tok, func(t *testing.T) {
			_, err := w.a.c.RevokeOwnPAT(context.Background(), uid, id)
			require.NoError(t, err)
		}}
	}},
	{"pat_expired", "pat", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, _ := awMintUser(t, w, seq, "awdpatexp")
		future := time.Now().UTC().Add(24 * time.Hour)
		tok, id := awMintPAT(t, w, uid, &future)
		return awDeadCred{tok, func(t *testing.T) {
			past := time.Now().UTC().Add(-time.Hour)
			require.NoError(t, w.a.db.Model(&models.PersonalAccessToken{}).Where("id = ?", id).Update("expires_at", past).Error)
		}}
	}},
	{"pat_of_suspended_user", "pat", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, _ := awMintUser(t, w, seq, "awdpatsusp")
		tok, _ := awMintPAT(t, w, uid, nil)
		return awDeadCred{tok, func(t *testing.T) { require.NoError(t, w.a.c.SuspendUser(context.Background(), w.adminID, uid)) }}
	}},
	{"pat_of_deleted_user", "pat", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		uid, _ := awMintUser(t, w, seq, "awdpatdel")
		tok, _ := awMintPAT(t, w, uid, nil)
		return awDeadCred{tok, func(t *testing.T) { require.NoError(t, w.a.c.DeleteUser(context.Background(), w.adminID, uid)) }}
	}},
	{"machine_identity_revoked", "machine", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		return awMintMachine(t, w, seq, "revoked")
	}},
	{"machine_identity_suspended", "machine", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		return awMintMachine(t, w, seq, "suspended")
	}},
	{"machine_token_project_deleted", "machine", func(t *testing.T, w *awWorld, seq int) awDeadCred {
		ctx := context.Background()
		p, err := w.a.c.CreateProject(ctx, fmt.Sprintf("awdoomed%d", seq), "")
		require.NoError(t, err)
		m, err := w.a.c.CreateMachineIdentity(ctx, p.ID, "doomed-bot", "service", "", "", w.adminID, 0)
		require.NoError(t, err)
		tok, err := w.a.c.IssueMachineToken(ctx, p.ID, m.ID, w.adminID, core.IssueMachineTokenParams{Name: "doomed"})
		require.NoError(t, err)
		return awDeadCred{tok.PlainToken, func(t *testing.T) { require.NoError(t, w.a.c.DeleteProject(ctx, p.ID, true)) }}
	}},
}

func awMintMachine(t *testing.T, w *awWorld, seq int, to string) awDeadCred {
	t.Helper()
	ctx := context.Background()
	m, err := w.a.c.CreateMachineIdentity(ctx, w.projID, fmt.Sprintf("aw-dead-%s-%d", to, seq), "service", "", "", w.adminID, 0)
	require.NoError(t, err)
	tok, err := w.a.c.IssueMachineToken(ctx, w.projID, m.ID, w.adminID, core.IssueMachineTokenParams{Name: "aw-dead"})
	require.NoError(t, err)
	return awDeadCred{tok.PlainToken, func(t *testing.T) {
		_, terr := w.a.c.TransitionMachineIdentity(ctx, w.projID, m.ID, to, w.adminID)
		require.NoError(t, terr)
	}}
}

func TestEveryRouteRefusesADeadCredential(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { awDeadWalk(t, backend) })
	}
}

func awDeadWalk(t *testing.T, backend string) {
	w := newAWWorld(t, backend, 2)
	b := w.b
	routes := awWalkRoutes(t, b.router)
	require.Greater(t, len(routes), 300, "sanity: the walk should find the whole router")
	tables := awTables(t, b.db)

	// Non-vacuity: a LIVE credential of each kind is served on the same replica, so a
	// 401 below is the credential's death and not a broken request.
	liveSession := w.tokens["awviewer"]
	for name, tok := range map[string]string{"session": liveSession, "machine": w.tokens["machine_zero"]} {
		code, body := awDo(b, http.MethodGet, tok, "/api/v1/auth/profile", nil)
		if name == "session" {
			require.Equal(t, http.StatusOK, code, "live session must authenticate: %s", body)
		} else {
			require.NotEqual(t, http.StatusUnauthorized, code, "live machine token must authenticate: %s", body)
		}
	}
	patTok, _ := awMintPAT(t, w, w.userIDs["awviewer"], nil)
	code, body := awDo(b, http.MethodGet, patTok, "/api/v1/auth/profile", nil)
	require.Equal(t, http.StatusOK, code, "live PAT must authenticate: %s", body)

	violations := map[string][]string{}
	seen := 0
	note := func(key, v string) {
		if len(violations[key]) < 4 {
			violations[key] = append(violations[key], v)
		}
	}
	seq := 0
	for _, st := range awDeadStates {
		for _, variant := range []string{"cold", "warm"} {
			seq++
			cred := st.mint(t, w, seq)
			if variant == "warm" {
				// One successful call on B fills B's cache. A machine token with no role
				// is authenticated here too (the profile route answers it 403, not 401).
				code, body := awDo(b, http.MethodGet, cred.token, "/api/v1/auth/profile", nil)
				require.NotEqual(t, http.StatusUnauthorized, code, "%s/warm: the live credential must authenticate before it is ended: %s", st.name, body)
				code, _ = awDo(b, http.MethodGet, cred.token, "/api/v1/auth/profile", nil)
				require.NotEqual(t, http.StatusUnauthorized, code, "%s/warm: and be served from the cache", st.name)
			}
			cred.end(t)
			if why := awDeadOpen[st.name]; why != "" {
				code, _ := awDo(b, http.MethodGet, cred.token, "/api/v1/auth/profile", nil)
				assert.NotEqual(t, http.StatusUnauthorized, code,
					"%s now answers 401: the open finding (%s) is fixed, remove its awDeadOpen entry", st.name, why)
			}

			want := awDeadWant(st.name)
			for _, rt := range routes {
				public := false
				if _, ok := awPublicRoutes[rt.key()]; ok {
					public = true
				} else if !strings.HasPrefix(rt.Path, "/api/v1/") {
					awClassify(t, rt) // reports the unclassified route
					continue
				}
				path := w.awPaths(rt.Path)[0]
				var reqBody []byte
				if awIsMutating(rt.Method) {
					reqBody = w.awBodyN(seq)
				}
				// Metrics/static/status/health routes carry no principal: nothing to refuse.
				if public && rt.Method == http.MethodGet {
					continue
				}
				before := awTakeDigest(t, b.db, tables)
				code, resp := awDo(b, rt.Method, cred.token, path, reqBody)
				after := awTakeDigest(t, b.db, tables)
				seen++
				key := fmt.Sprintf("%s/%s %s", st.name, variant, rt.key())
				switch {
				case awFeatureOff(code, resp):
				case code >= 500 && st.kind == "machine" && (awKnownOpen["machine_zero "+rt.key()] != "" || awKnownOpenMachineGET[rt.key()]):
					// #3416 (open) fixes the machine 5xx on these user-only routes.
				case code >= 500:
					note(key, fmt.Sprintf("%d (a 5xx is a finding by itself): %.160s", code, resp))
				case public:
					wantLogout := http.StatusUnauthorized
					if c, ok := awDeadLogout[st.name]; ok {
						wantLogout = c
					}
					if rt.key() == "POST /auth/logout" && st.kind == "session" && code != wantLogout {
						note(key, fmt.Sprintf("%d, a dead session on logout must be %d (INV-HTTP-17): %.160s", code, wantLogout, resp))
					}
				case awDeadOpen[st.name] != "":
				case code != want:
					note(key, fmt.Sprintf("%d, want %d: %.160s", code, want, resp))
				}
				side := awDeadSideTables[st.name]
				if rt.key() == "POST /auth/logout" && st.name == "session_expired" {
					side = append([]string{"sessions"}, side...) // the cleanup drops the dead session row
				}
				d := awDiff(before, after, 0, side...)
				if rt.key() == "POST /auth/logout" && st.name == "session_expired" {
					d = slices.DeleteFunc(d, func(l string) bool { return strings.Contains(l, `"auth.logout"`) })
				}
				if len(d) > 0 {
					note(key, fmt.Sprintf("status %d but state changed: %s", code, strings.Join(d, " | ")))
				}
			}
		}
	}
	require.Greater(t, seen, 2*len(awDeadStates)*300, "sanity: every state x variant must walk the whole router")

	keys := make([]string, 0, len(violations))
	for k := range violations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("%s: %s", k, strings.Join(violations[k], "\n    "))
	}
	assert.NotEmpty(t, awDeadStates)
}
