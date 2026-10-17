package http

// PERF-FIX-3 (PERF-6 ranked fix #3, collapse C1): a human value read
// (GET /secrets/{id}?include_value=true) evaluated the same read-permission check
// twice, GetSecretWithPermissionCheck then GetSecretValueWithPermissionCheck, with
// the same arguments, and fetched the secret again in between. The value step now
// reuses the first check (core.GetSecretForValueRead / GetPermittedSecretValue).
//
// TestValueReadAuthorizeOnce_Equivalence is the behaviour pin: the authz outcome,
// the response and the audit rows for every case below. It passes unchanged on the
// code before this change and after it (it uses nothing the change added), which is
// the before/after equivalence. TestValueReadAuthorizeOnce_ChecksOnce is the
// red/green: before, a value read ran the per-secret share lookup of
// CheckSecretPermission twice; after, once.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers"
)

const voPassword = "Qr7#Kp2$Lm5@Vn9!"

// voReplica is one server process: its own *gorm.DB pool, its own LocalStorage
// (own read-path caches), its own core and router.
type voReplica struct {
	c   *core.KeyorixCore
	db  *gorm.DB
	srv *httptest.Server

	mu          sync.Mutex
	counting    bool
	stmts       int
	shareLookup int
}

// voWorld is the fixture shared by every case: users and their tokens, one project
// with two environments, and a second project for the cross-project case.
type voWorld struct {
	a, b       *voReplica // b is nil unless a second replica was asked for
	adminID    uint
	projectID  uint
	envA, envB uint
	users      map[string]uint
	tokens     map[string]string
	otherProj  uint
	otherEnv   uint
	secretSeq  atomic.Int64
}

var voSchemaSeq atomic.Int64

func voOpenStorage(t *testing.T, backend string) (storageCfg *config.Config, pgTarget string) {
	t.Helper()
	switch backend {
	case "sqlite":
		return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxvo_")}}}, ""
	case "postgres":
		pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
		if pgDSN == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("perffix3_vo_%d_%d", os.Getpid(), voSchemaSeq.Add(1))
		admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
		target := pgdsn.PGSearchPathDSN(pgDSN, schema)
		return &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: target}}}, target
	}
	t.Fatalf("unknown backend %q", backend)
	return nil, ""
}

func voNewReplica(t *testing.T, st *store.LocalStorage) *voReplica {
	t.Helper()
	r := &voReplica{c: core.NewKeyorixCore(st), db: st.DB()}
	count := func(db *gorm.DB) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.counting {
			return
		}
		r.stmts++
		if strings.Contains(db.Statement.SQL.String(), "share_records") {
			r.shareLookup++
		}
	}
	cb := r.db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("perffix3:count_q", count))
	require.NoError(t, cb.Row().After("gorm:row").Register("perffix3:count_row", count))
	r.c.SetBootstrapToken("test-bootstrap-token")
	return r
}

func (r *voReplica) serve(t *testing.T) {
	t.Helper()
	r.srv = newSecretsMachineTestServer(t, r.c)
	t.Cleanup(r.srv.Close)
}

// newVOWorld builds the world through the production storage factory (so the
// read-path caches, the cache_epoch trigger and the role-permission cache are the
// production ones). With twoReplicas (Postgres only) a second, independent pool
// and LocalStorage serve the same schema.
func newVOWorld(t *testing.T, backend string, twoReplicas bool) *voWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg, pgTarget := voOpenStorage(t, backend)
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	t.Cleanup(func() { _ = ls.Close() }) // every pool it opened, the native read pool included
	w := &voWorld{a: voNewReplica(t, ls), users: map[string]uint{}, tokens: map[string]string{}}
	if twoReplicas {
		require.NotEmpty(t, pgTarget, "two replicas need Postgres")
		db, oerr := gorm.Open(postgres.Open(pgTarget), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, oerr)
		sqlDB, derr := db.DB()
		require.NoError(t, derr)
		t.Cleanup(func() { _ = sqlDB.Close() })
		w.b = voNewReplica(t, store.NewLocalStorage(db))
	}

	c, ctx := w.a.c, context.Background()
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "voadmin", Email: "voadmin@example.com", Password: voPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "voadmin@example.com")
	require.NoError(t, err)
	w.adminID = admin.ID

	project, err := c.CreateProject(ctx, "vo-project", "value read authorize once")
	require.NoError(t, err)
	w.projectID = project.ID
	envA, err := c.CreateEnvironment(ctx, project.ID, "vo-env-a")
	require.NoError(t, err)
	envB, err := c.CreateEnvironment(ctx, project.ID, "vo-env-b")
	require.NoError(t, err)
	w.envA, w.envB = envA.ID, envB.ID
	other, err := c.CreateProject(ctx, "vo-other", "cross-project")
	require.NoError(t, err)
	otherEnv, err := c.CreateEnvironment(ctx, other.ID, "vo-other-env")
	require.NoError(t, err)
	w.otherProj, w.otherEnv = other.ID, otherEnv.ID

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	roleID := map[string]uint{}
	for _, r := range roles {
		roleID[r.Name] = r.ID
	}

	mk := func(name string) uint {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: voPassword})
		require.NoError(t, uerr)
		w.users[name] = u.ID
		return u.ID
	}
	// owner: project_developer at the project, creates the secrets and shares them.
	require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk("owner"), roleID["project_developer"], core.Scope{ProjectID: project.ID}, false))
	// dev: project_viewer at the project (role grants secrets.read on every env).
	require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk("dev"), roleID["project_viewer"], core.Scope{ProjectID: project.ID}, false))
	// sharee / aclUser: project members only through a role on env B, so their
	// role does NOT reach secrets in env A; a share / an ACL grant does.
	require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk("sharee"), roleID["project_viewer"], core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID}, false))
	require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk("acluser"), roleID["project_viewer"], core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID}, false))
	// outsider: project_developer in the OTHER project only.
	require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk("outsider"), roleID["project_developer"], core.Scope{ProjectID: other.ID}, false))

	for _, name := range []string{"owner", "dev", "sharee", "acluser", "outsider"} {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: name, Password: voPassword})
		require.NoError(t, lerr, name)
		w.tokens[name] = sess.SessionToken
	}
	w.a.serve(t)
	if w.b != nil {
		w.b.serve(t)
	}
	return w
}

// newSecret creates a fresh env-A secret owned by "owner", so cases never share state.
func (w *voWorld) newSecret(t *testing.T) *models.SecretNode {
	t.Helper()
	n := w.secretSeq.Add(1)
	s, err := w.a.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: fmt.Sprintf("vo-secret-%d", n), Value: []byte(fmt.Sprintf("vo-value-%d", n)),
		ProjectID: w.projectID, EnvironmentID: w.envA, Type: "generic",
		CreatedBy: "owner", OwnerID: w.users["owner"],
	})
	require.NoError(t, err)
	return s
}

type voOutcome struct {
	Status   int
	ErrCode  string
	ErrMsg   string
	Value    string
	SecretID uint
	// audit/access-log rows this request added for the secret
	ReadEvents int
	ReadLogs   int
	EventUser  uint
	EventProj  uint
	EventOK    bool
	EventActor string
}

func (r *voReplica) valueRead(t *testing.T, token string, secretID uint) voOutcome {
	t.Helper()
	ctx := context.Background()
	beforeEv, beforeLog := r.readRows(t, secretID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/secrets/%d?include_value=true", r.srv.URL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()

	out := voOutcome{Status: resp.StatusCode}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Data    struct {
			Value  string `json:"value"`
			Secret struct {
				ID uint `json:"ID"`
			} `json:"secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	out.ErrCode, out.ErrMsg = body.Error, body.Message
	out.Value, out.SecretID = body.Data.Value, body.Data.Secret.ID

	afterEv, afterLog := r.readRows(t, secretID)
	out.ReadEvents, out.ReadLogs = len(afterEv)-len(beforeEv), len(afterLog)-len(beforeLog)
	if len(afterEv) > len(beforeEv) {
		ev := afterEv[len(afterEv)-1]
		if ev.UserID != nil {
			out.EventUser = *ev.UserID
		}
		if ev.ProjectID != nil {
			out.EventProj = *ev.ProjectID
		}
		out.EventOK, out.EventActor = ev.Success != nil && *ev.Success, ev.ActorType
	}
	return out
}

func (r *voReplica) readRows(t *testing.T, secretID uint) ([]models.AuditEvent, []models.SecretAccessLog) {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, r.db.Where("secret_node_id = ? AND event_type = ?", secretID, "secret.read").Order("id").Find(&evs).Error)
	var logs []models.SecretAccessLog
	require.NoError(t, r.db.Where("secret_node_id = ? AND action = ?", secretID, "read").Order("id").Find(&logs).Error)
	return evs, logs
}

// allowed is the outcome of a successful value read by user on s.
func (w *voWorld) allowed(s *models.SecretNode, user string) voOutcome {
	return voOutcome{
		Status: http.StatusOK, Value: strings.Replace(s.Name, "vo-secret-", "vo-value-", 1), SecretID: s.ID,
		ReadEvents: 1, ReadLogs: 1, EventUser: w.users[user], EventProj: w.projectID, EventOK: true, EventActor: "user",
	}
}

func voDenied(status int, code, msg string) voOutcome {
	return voOutcome{Status: status, ErrCode: code, ErrMsg: msg}
}

// refusedBy is a secret-state refusal of user's read: since #3273 it writes one
// failed secret.read naming the secret (the caller was authorized to see it),
// and no access-log row. A permission refusal names no secret, so it adds no
// row readRows sees and stays a plain voDenied.
func (w *voWorld) refusedBy(user string, o voOutcome) voOutcome {
	o.ReadEvents, o.EventUser, o.EventProj, o.EventOK, o.EventActor = 1, w.users[user], w.projectID, false, "user"
	return o
}

// notTodayOrTomorrow is an AllowedDays list excluding today and tomorrow (UTC), so
// a schedule built from it denies for the whole run even across midnight.
func notTodayOrTomorrow() string {
	iso := func(d time.Weekday) int {
		if d == time.Sunday {
			return 7
		}
		return int(d)
	}
	now := time.Now().UTC()
	skip := map[int]bool{iso(now.Weekday()): true, iso(now.Add(24 * time.Hour).Weekday()): true}
	var days []string
	for d := 1; d <= 7; d++ {
		if !skip[d] {
			days = append(days, strconv.Itoa(d))
		}
	}
	return strings.Join(days, ",")
}

func TestValueReadAuthorizeOnce_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { voEquivalence(t, backend) })
	}
}

func voEquivalence(t *testing.T, backend string) {
	w := newVOWorld(t, backend, false)
	c, ctx, r := w.a.c, context.Background(), w.a
	share := func(s *models.SecretNode, recipient string) uint {
		rec, err := c.ShareSecret(ctx, &core.ShareSecretRequest{
			SecretID: s.ID, RecipientID: w.users[recipient], Permission: "read", SharedBy: w.users["owner"],
		})
		require.NoError(t, err)
		return rec.ID
	}
	forbidden := voDenied(http.StatusForbidden, "Forbidden", "Insufficient permissions")

	cases := []struct {
		name  string
		user  string
		setup func(s *models.SecretNode)
		want  func(s *models.SecretNode) voOutcome
	}{
		{"role grant", "dev", nil, func(s *models.SecretNode) voOutcome { return w.allowed(s, "dev") }},
		{"live owner", "owner", nil, func(s *models.SecretNode) voOutcome { return w.allowed(s, "owner") }},
		{"read share", "sharee", func(s *models.SecretNode) { share(s, "sharee") },
			func(s *models.SecretNode) voOutcome { return w.allowed(s, "sharee") }},
		{"revoked share", "sharee", func(s *models.SecretNode) {
			require.NoError(t, c.RevokeShare(ctx, share(s, "sharee"), w.users["owner"]))
		}, func(*models.SecretNode) voOutcome { return forbidden }},
		{"expired share", "sharee", func(s *models.SecretNode) {
			id := share(s, "sharee")
			// Through Save(), so ShareRecord's BeforeSave hook runs (G1619).
			var rec models.ShareRecord
			require.NoError(t, r.db.First(&rec, id).Error)
			past := time.Now().Add(-time.Minute)
			rec.ExpiresAt = &past
			require.NoError(t, r.db.Save(&rec).Error)
		}, func(*models.SecretNode) voOutcome { return forbidden }},
		{"acl grant", "acluser", func(s *models.SecretNode) {
			require.NoError(t, c.GrantSecretACL(ctx, w.adminID, s.ID, w.users["acluser"], []string{"secrets.read"}))
		}, func(s *models.SecretNode) voOutcome { return w.allowed(s, "acluser") }},
		{"no grant (member of another env only)", "acluser", nil, func(*models.SecretNode) voOutcome { return forbidden }},
		{"cross-project", "outsider", nil, func(*models.SecretNode) voOutcome { return forbidden }},
		{"deleted", "dev", func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
			func(*models.SecretNode) voOutcome { return forbidden }}, // the gate answers a deleted secret like an ungranted one (no existence oracle)
		// ERRMAP-1 changed the secret-state refusals below (and max reads) from
		// 500/Internal to their own status and fixed message.
		{"suspended", "dev", func(s *models.SecretNode) {
			_, err := c.SuspendSecret(ctx, s.ID, w.adminID, "perf-fix-3 equivalence")
			require.NoError(t, err)
		}, func(*models.SecretNode) voOutcome {
			return w.refusedBy("dev", voDenied(http.StatusConflict, "SecretSuspended", "secret is suspended; its value cannot be read until it is resumed"))
		}},
		{"expired", "dev", func(s *models.SecretNode) {
			// Through Save(), so SecretNode's BeforeSave hook runs (G1619).
			var row models.SecretNode
			require.NoError(t, r.db.First(&row, s.ID).Error)
			past := time.Now().Add(-time.Minute)
			row.Expiration = &past
			require.NoError(t, r.db.Save(&row).Error)
		}, func(*models.SecretNode) voOutcome {
			return w.refusedBy("dev", voDenied(http.StatusConflict, "SecretExpired", "secret has expired; its value can no longer be read"))
		}},
		{"schedule denies", "dev", func(s *models.SecretNode) {
			_, err := c.SetSecretSchedule(ctx, s.ID, notTodayOrTomorrow(), 0, 24, "UTC")
			require.NoError(t, err)
		}, func(*models.SecretNode) voOutcome {
			return w.refusedBy("dev", voDenied(http.StatusForbidden, "SecretAccessOutsideSchedule", core.ErrAccessOutsideSchedule.Error()))
		}},
		{"schedule allows", "dev", func(s *models.SecretNode) {
			_, err := c.SetSecretSchedule(ctx, s.ID, "*", 0, 24, "UTC")
			require.NoError(t, err)
		}, func(s *models.SecretNode) voOutcome { return w.allowed(s, "dev") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := w.newSecret(t)
			// Warm every read-path cache on an allowed read first, so a stale cache
			// entry would show as a wrong outcome below.
			require.Equal(t, http.StatusOK, r.valueRead(t, w.tokens["owner"], s.ID).Status)
			if tc.setup != nil {
				tc.setup(s)
			}
			assert.Equal(t, tc.want(s), r.valueRead(t, w.tokens[tc.user], s.ID))
		})
	}

	t.Run("max reads exhausted", func(t *testing.T) {
		s := w.newSecret(t)
		one := 1
		_, err := c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: s.ID, MaxReads: &one, UpdatedBy: "owner"})
		require.NoError(t, err)
		assert.Equal(t, w.allowed(s, "dev"), r.valueRead(t, w.tokens["dev"], s.ID))
		assert.Equal(t, w.refusedBy("dev", voDenied(http.StatusConflict, "SecretMaxReadsExhausted", "secret has reached its maximum number of reads")),
			r.valueRead(t, w.tokens["dev"], s.ID))
	})
}

// TestValueReadAuthorizeOnce_CrossReplica: replica A serves the reads with warm
// caches while replica B (own pool, own caches, same Postgres schema) commits the
// change. A's very next read must reflect it, exactly as before.
func TestValueReadAuthorizeOnce_CrossReplica(t *testing.T) {
	w := newVOWorld(t, "postgres", true)
	a, b, ctx := w.a, w.b, context.Background()
	forbidden := voDenied(http.StatusForbidden, "Forbidden", "Insufficient permissions")

	cases := []struct {
		name   string
		user   string
		before func(s *models.SecretNode) // on A, before the warm read
		change func(s *models.SecretNode) // committed on B
		want   func(s *models.SecretNode) voOutcome
	}{
		{"share revoked on B", "sharee", nil, nil, func(*models.SecretNode) voOutcome { return forbidden }},
		{"role removed on B", "dev", nil, func(*models.SecretNode) {
			roles, err := b.c.Storage().ListRoles(ctx)
			require.NoError(t, err)
			for _, r := range roles {
				if r.Name == "project_viewer" {
					require.NoError(t, b.c.RemoveUserRole(ctx, w.adminID, w.users["dev"], r.ID, core.Scope{ProjectID: w.projectID}))
				}
			}
		}, func(*models.SecretNode) voOutcome { return forbidden }},
		{"suspended on B", "owner", nil, func(s *models.SecretNode) {
			_, err := b.c.SuspendSecret(ctx, s.ID, w.adminID, "perf-fix-3 cross-replica")
			require.NoError(t, err)
		}, func(*models.SecretNode) voOutcome {
			return w.refusedBy("owner", voDenied(http.StatusConflict, "SecretSuspended", "secret is suspended; its value cannot be read until it is resumed"))
		}},
		{"deleted on B", "owner", nil, func(s *models.SecretNode) { require.NoError(t, b.c.DeleteSecret(ctx, s.ID)) },
			func(*models.SecretNode) voOutcome { return forbidden }}, // the gate answers a deleted secret like an ungranted one (no existence oracle)
		{"schedule set on B", "owner", nil, func(s *models.SecretNode) {
			_, err := b.c.SetSecretSchedule(ctx, s.ID, notTodayOrTomorrow(), 0, 24, "UTC")
			require.NoError(t, err)
		}, func(*models.SecretNode) voOutcome {
			return w.refusedBy("owner", voDenied(http.StatusForbidden, "SecretAccessOutsideSchedule", core.ErrAccessOutsideSchedule.Error()))
		}},
		{"value rotated on B", "owner", nil, func(s *models.SecretNode) {
			_, err := b.c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: s.ID, Value: []byte("rotated-on-b"), UpdatedBy: "owner"})
			require.NoError(t, err)
		}, func(s *models.SecretNode) voOutcome {
			o := w.allowed(s, "owner")
			o.Value = "rotated-on-b"
			return o
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := w.newSecret(t)
			var shareID uint
			if tc.user == "sharee" {
				rec, err := a.c.ShareSecret(ctx, &core.ShareSecretRequest{
					SecretID: s.ID, RecipientID: w.users["sharee"], Permission: "read", SharedBy: w.users["owner"],
				})
				require.NoError(t, err)
				shareID = rec.ID
			}
			require.Equal(t, http.StatusOK, a.valueRead(t, w.tokens[tc.user], s.ID).Status, "warm read on A")
			if tc.change != nil {
				tc.change(s)
			} else {
				require.NoError(t, b.c.RevokeShare(ctx, shareID, w.users["owner"]))
			}
			assert.Equal(t, tc.want(s), a.valueRead(t, w.tokens[tc.user], s.ID))
		})
	}
}

// TestValueReadAuthorizeOnce_ChecksOnce is the red/green for the collapse: a human
// value read evaluates its per-secret decision once. Measured as the per-secret share
// lookup, which only CheckSecretPermission issues for a role-holding reader (the
// middleware gate consults shares only after ACL and role both said no); since
// OPT-READPATH-2 the core read check reuses the gate's allow, so it issues none.
func TestValueReadAuthorizeOnce_ChecksOnce(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newVOWorld(t, backend, false)
			s := w.newSecret(t)
			r := w.a
			require.Equal(t, http.StatusOK, r.valueRead(t, w.tokens["dev"], s.ID).Status, "warm")
			r.mu.Lock()
			r.counting, r.stmts, r.shareLookup = true, 0, 0
			r.mu.Unlock()
			out := r.valueRead(t, w.tokens["dev"], s.ID)
			r.mu.Lock()
			r.counting = false
			stmts, shares := r.stmts, r.shareLookup
			r.mu.Unlock()
			require.Equal(t, http.StatusOK, out.Status)
			t.Logf("%s: human value read issued %d read statements (GORM; audit flusher writes not counted)", backend, stmts)
			// OPT-READPATH-2: the core read check now reuses the gate's allow (the role
			// granted it, so the gate never reached the share term), so no share lookup at
			// all; before PERF-FIX-3 there were two, before OPT-READPATH-2 one.
			assert.Equal(t, 0, shares, "the per-secret decision must be evaluated once per value read, by the gate")
		})
	}
}
