package http

// session_cache_hit_live_check_test.go — PERF-FIX-7 (collapse C6 of
// SESSION-PERF-FIX-3's plan).
//
// An interactive session's auth-cache hit (server/middleware serveAuthCacheHit)
// re-read two rows on every request: the owning account
// (AccountUsabilityAndState -> GetUser) and the session row itself
// (SessionLiveForToken -> GetSessionByID). They are now one statement
// (storage.GetSessionAuthLiveness).
//
// TestSessionCacheHitLiveCheck_Equivalence is the behaviour pin: for every case
// below it warms the cache on replica A, changes the world through replica B
// (own pool, own caches, no cache invalidator wired, so only A's cache-hit
// re-read can notice), and records the status and body of the next two
// requests on A. It uses nothing the change added and passes unchanged on the
// code before the change and after it: that is the before/after equivalence.
// _Invalidation checks that the same changes made through the replica that owns
// the cache still evict it. _CrossReplicaRace races a revoke / suspend on B
// against a request loop on A (Postgres, two pools). _OneStatement is the
// red/green: before, a cache hit issued 2 statements on users/sessions; after, 1.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const lcPassword = "Qr7#Kp2$Lm5@Vn9!"

// lcRoute is authenticated but not permission-gated, and is not on
// EnforceAccountSetup's allowlist, so a restricted account gets 403 there.
const lcRoute = "/api/v1/notifications"

type lcWorld struct {
	backend string
	a, b    *svReplica
	adminID uint
	projID  uint
	seq     atomic.Int64
}

func newLCWorld(t *testing.T, backend string) *lcWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := svStorageConfig(t, backend)
	w := &lcWorld{backend: backend, a: newSVReplica(t, cfg), b: newSVReplica(t, cfg)}
	c, db, ctx := w.a.c, w.a.db, context.Background()
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "lcadmin", Email: "lcadmin@example.com", Password: lcPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	var admin models.User
	require.NoError(t, db.Where("username = ?", "lcadmin").First(&admin).Error)
	w.adminID = admin.ID
	proj, err := c.CreateProject(ctx, "lcproj", "")
	require.NoError(t, err)
	w.projID = proj.ID
	var perm models.Permission
	require.NoError(t, db.Where("name = ?", "secrets.read").First(&perm).Error)
	role := models.Role{Name: lcEmergencyRole, NameFolded: lcEmergencyRole}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	return w
}

// lcEmergencyRole is the break-glass emergency role: contained (no roles.assign).
const lcEmergencyRole = "lc-emergency"

// user creates an active account with a project-scoped role and logs it in.
func (w *lcWorld) user(t *testing.T) (*models.User, string) {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("lcuser%d", w.seq.Add(1))
	u, err := w.a.c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@x.io", Password: lcPassword})
	require.NoError(t, err)
	var role models.Role
	require.NoError(t, w.a.db.Where("name = ?", "project_viewer").First(&role).Error)
	require.NoError(t, w.a.c.AssignUserRole(ctx, 0, u.ID, role.ID, core.Scope{ProjectID: w.projID}, false))
	return u, w.login(t, name)
}

func (w *lcWorld) login(t *testing.T, username string) string {
	t.Helper()
	sess, _, err := w.a.c.Login(context.Background(), &core.LoginRequest{Username: username, Password: lcPassword})
	require.NoError(t, err)
	return sess.SessionToken
}

// lcGet issues one authenticated request on r and returns "status body".
func lcGet(r *svReplica, token string) string {
	req := httptest.NewRequest(http.MethodGet, lcRoute, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		return "200"
	}
	return fmt.Sprintf("%d %s", rec.Code, svNormalizeBody(rec.Body.String()))
}

func lcSessionRow(t *testing.T, db *gorm.DB, token string) *models.Session {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	var s models.Session
	require.NoError(t, db.Where("session_token = ?", hex.EncodeToString(sum[:])).First(&s).Error)
	return &s
}

func lcUserRow(t *testing.T, db *gorm.DB, id uint) *models.User {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, id).Error)
	return &u
}

const (
	lc401 = "401 code=401;error=Unauthorized;message=Invalid or expired token;"
	lc403 = "403 code=403;error=PasswordChangeRequired;message=You must change your password before continuing.;pending_steps=[change_password];"
)

type lcCase struct {
	name string
	// change runs on replica b (or a, for _Invalidation) after the token's
	// cache entry is warm on a. It returns the token to present afterwards
	// ("" = the warmed token).
	change func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, token string) string
	want   [2]string // next two requests on a
	// wantEvicted, when set, is the answer when the change runs on the replica
	// that owns the cache (_Invalidation): a change whose own eviction
	// tombstones the token answers 401 there before any re-read happens.
	wantEvicted *[2]string
}

func lcCases() []lcCase {
	ctx := context.Background()
	return []lcCase{
		{name: "active user, live session", want: [2]string{"200", "200"},
			change: func(*testing.T, *lcWorld, *svReplica, *models.User, string) string { return "" }},
		{name: "suspended (admin action, sessions swept)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				require.NoError(t, on.c.SuspendUser(ctx, w.adminID, u.ID))
				return ""
			}},
		{name: "suspended (account state only, session row intact)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				uu.AccountState = core.AccountSuspended
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "deactivated (is_active false, session row intact)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				uu.IsActive = false
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "deactivated (UpdateUser)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				inactive := false
				_, err := on.c.UpdateUser(ctx, &core.UpdateUserRequest{ID: u.ID, ActorID: w.adminID, IsActive: &inactive})
				require.NoError(t, err)
				return ""
			}},
		{name: "login-locked (lockout is a login-time control only)", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				until := time.Now().Add(time.Hour).UTC()
				uu.LoginLockedUntil = &until
				uu.FailedLoginAttempts = 10
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "deleted user (DeleteUser)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				require.NoError(t, on.c.DeleteUser(ctx, w.adminID, u.ID))
				return ""
			}},
		{name: "soft-deleted user row, session row intact", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				require.NoError(t, on.db.Delete(&models.User{}, u.ID).Error)
				return ""
			}},
		{name: "password reset required (restricted, not blocked)", want: [2]string{lc403, lc403}, wantEvicted: &[2]string{lc401, lc401},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				require.NoError(t, on.c.RequirePasswordReset(ctx, w.adminID, u.ID))
				return ""
			}},
		{name: "pending first login (restricted, not blocked)", want: [2]string{lc403, lc403},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				uu.AccountState = core.AccountPendingFirstLogin
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "reactivated after suspension (session row intact)", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				uu.AccountState = core.AccountSuspended
				require.NoError(t, on.db.Save(uu).Error)
				uu.AccountState = core.AccountActive
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "session revoked (RevokeUserSessions)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				_, err := on.c.RevokeUserSessions(ctx, w.adminID, u.ID)
				require.NoError(t, err)
				return ""
			}},
		{name: "session idle-timed-out (expires_at passed)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, _ *models.User, token string) string {
				s := lcSessionRow(t, on.db, token)
				past := time.Now().Add(-time.Minute).UTC()
				s.ExpiresAt = &past
				require.NoError(t, on.db.Save(s).Error)
				return ""
			}},
		{name: "session past its absolute ceiling", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, _ *models.User, token string) string {
				s := lcSessionRow(t, on.db, token)
				past := time.Now().Add(-time.Minute).UTC()
				s.AbsoluteExpiresAt = &past
				require.NoError(t, on.db.Save(s).Error)
				return ""
			}},
		{name: "session rotated (old token presented)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, _ *models.User, token string) string {
				_, err := on.c.RefreshSession(ctx, token)
				require.NoError(t, err)
				return ""
			}},
		{name: "session rotated (new token presented)", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, _ *models.User, token string) string {
				ns, err := on.c.RefreshSession(ctx, token)
				require.NoError(t, err)
				return ns.SessionToken
			}},
		{name: "password changed after the session (other sessions dropped)", want: [2]string{lc401, lc401},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				require.NoError(t, on.c.ChangePassword(ctx, u.ID, lcPassword, "Zx8#Wq3$Pn6@Tm1!", ""))
				return ""
			}},
		{name: "another user's session revoked", want: [2]string{"200", "200"},
			change: func(t *testing.T, w *lcWorld, on *svReplica, _ *models.User, _ string) string {
				other, _ := w.user(t)
				_, err := on.c.RevokeUserSessions(ctx, w.adminID, other.ID)
				require.NoError(t, err)
				return ""
			}},
		{name: "another user's session token presented (never warmed)", want: [2]string{"200", "200"},
			change: func(t *testing.T, w *lcWorld, _ *svReplica, _ *models.User, _ string) string {
				_, tok := w.user(t)
				return tok
			}},
		{name: "setup-only flag set after the session was cached", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, _ *models.User, token string) string {
				s := lcSessionRow(t, on.db, token)
				s.SetupOnly = true
				require.NoError(t, on.db.Save(s).Error)
				return ""
			}},
		{name: "MFA enabled after the session (no session sweep)", want: [2]string{"200", "200"},
			change: func(t *testing.T, _ *lcWorld, on *svReplica, u *models.User, _ string) string {
				uu := lcUserRow(t, on.db, u.ID)
				uu.MFAEnabled = true
				require.NoError(t, on.db.Save(uu).Error)
				return ""
			}},
		{name: "break-glass activated, then revoked", want: [2]string{"200", "200"},
			change: func(t *testing.T, w *lcWorld, on *svReplica, u *models.User, _ string) string {
				on.c.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: true, EmergencyRole: lcEmergencyRole, DefaultTTL: time.Hour, MaxTTL: time.Hour})
				act, err := on.c.ActivateBreakGlass(ctx, w.projID, u.ID, "incident 1234: production outage triage", "")
				require.NoError(t, err)
				require.NoError(t, on.c.RevokeBreakGlass(ctx, w.adminID, 0, w.projID, act.ID))
				return ""
			}},
	}
}

func lcRun(t *testing.T, w *lcWorld, tc lcCase, on *svReplica) [2]string {
	t.Helper()
	u, token := w.user(t)
	require.Equal(t, "200", lcGet(w.a, token), "slow path fills the cache")
	require.Equal(t, "200", lcGet(w.a, token), "warm cache hit")
	if next := tc.change(t, w, on, u, token); next != "" {
		token = next
	}
	return [2]string{lcGet(w.a, token), lcGet(w.a, token)}
}

// TestSessionCacheHitLiveCheck_Equivalence: see the file header. B has no cache
// invalidator, so A's cache entry stays warm and A's cache-hit re-read decides.
func TestSessionCacheHitLiveCheck_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newLCWorld(t, backend)
			for _, tc := range lcCases() {
				t.Run(tc.name, func(t *testing.T) {
					require.Equal(t, tc.want, lcRun(t, w, tc, w.b))
				})
			}
		})
	}
}

// TestSessionCacheHitLiveCheck_Invalidation: the same changes made through the
// replica that owns the cache (invalidator wired, as server/main.go does) give
// the same answers: the cache-hit re-read and the eviction agree.
func TestSessionCacheHitLiveCheck_Invalidation(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newLCWorld(t, backend)
			w.a.c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
			for _, tc := range lcCases() {
				t.Run(tc.name, func(t *testing.T) {
					want := tc.want
					if tc.wantEvicted != nil {
						want = *tc.wantEvicted
					}
					require.Equal(t, want, lcRun(t, w, tc, w.a))
				})
			}
		})
	}
}

// TestSessionCacheHitLiveCheck_CrossReplicaRace: A serves a request loop for a
// warm session while B revokes the session or suspends the account. Every
// request that STARTED after B's write returned must be refused (no request
// may be served from a snapshot older than a committed revocation), and at
// least one request must have raced the write.
func TestSessionCacheHitLiveCheck_CrossReplicaRace(t *testing.T) {
	w := newLCWorld(t, "postgres")
	ctx := context.Background()
	writes := []struct {
		name  string
		write func(u *models.User, token string) error
	}{
		{"revoke sessions", func(u *models.User, _ string) error {
			_, err := w.b.c.RevokeUserSessions(ctx, w.adminID, u.ID)
			return err
		}},
		{"suspend user", func(u *models.User, _ string) error { return w.b.c.SuspendUser(ctx, w.adminID, u.ID) }},
		{"account state suspended, session intact", func(u *models.User, _ string) error {
			return w.b.db.Model(&models.User{}).Where("id = ?", u.ID).Update("account_state", core.AccountSuspended).Error
		}},
		{"session deleted", func(_ *models.User, token string) error {
			return w.b.db.Delete(lcSessionRow(t, w.b.db, token)).Error
		}},
	}
	for i := range 3 {
		for _, wr := range writes {
			t.Run(fmt.Sprintf("%s/%d", wr.name, i), func(t *testing.T) {
				u, token := w.user(t)
				require.Equal(t, "200", lcGet(w.a, token))
				type sample struct {
					start time.Time
					got   string
				}
				var (
					mu      sync.Mutex
					samples []sample
					stop    atomic.Bool
					wg      sync.WaitGroup
				)
				for range 4 {
					wg.Go(func() {
						for !stop.Load() {
							start := time.Now()
							got := lcGet(w.a, token)
							mu.Lock()
							samples = append(samples, sample{start, got})
							mu.Unlock()
						}
					})
				}
				time.Sleep(20 * time.Millisecond)
				require.NoError(t, wr.write(u, token))
				committed := time.Now()
				time.Sleep(40 * time.Millisecond)
				stop.Store(true)
				wg.Wait()
				before, after := 0, 0
				for _, s := range samples {
					if s.start.After(committed) {
						after++
						require.Equal(t, lc401, s.got, "a request started %v after the write returned", s.start.Sub(committed))
					} else if s.got == "200" {
						before++
					}
				}
				require.Positive(t, after, "no request started after the write (harness did not race)")
				require.Positive(t, before, "no request was served before the write (harness did not race)")
				require.Equal(t, lc401, lcGet(w.a, token))
			})
		}
	}
}

// lcLiveCheckTables matches a statement that reads users or sessions.
var lcLiveCheckTables = regexp.MustCompile(`(?i)\b(from|join)\s+["` + "`" + `]?(users|sessions)["` + "`" + `]?(\s|$)`)

// TestSessionCacheHitLiveCheck_OneStatement is the red/green: a warm session
// cache hit reads the account and the session row in ONE statement.
func TestSessionCacheHitLiveCheck_OneStatement(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newLCWorld(t, backend)
			_, token := w.user(t)
			require.Equal(t, "200", lcGet(w.a, token))
			require.Equal(t, "200", lcGet(w.a, token))
			w.a.mu.Lock()
			w.a.counting, w.a.stmts = true, nil
			w.a.mu.Unlock()
			require.Equal(t, "200", lcGet(w.a, token))
			w.a.mu.Lock()
			w.a.counting = false
			all := append([]string(nil), w.a.stmts...)
			w.a.mu.Unlock()
			var live []string
			for _, s := range all {
				if lcLiveCheckTables.MatchString(s) {
					live = append(live, s)
				}
			}
			t.Logf("%s: cache-hit request: %d statement(s), %d on users/sessions", backend, len(all), len(live))
			if len(live) != 1 {
				t.Errorf("a session cache hit must read the account and the session in ONE statement; got %d:\n%s",
					len(live), strings.Join(live, "\n"))
			}
		})
	}
}
