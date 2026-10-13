package http

// PERF-FIX-5 (PERF-FIX-3 collapses C2 + C3): two re-fetches of a secret the request
// had already resolved.
//   - C2: RequireScopedSecretPermission (and RequireScopedSecretRefPermission) resolve
//     the secret and hand it to core.AuthorizeSecretPrincipalForSecretAction, whose
//     human branch (AuthorizeSecretAction) fetched the same row again.
//   - C3: GetSecretWithPermissionCheck ran checkSecretPermission, which fetches the
//     secret, then fetched it again with GetSecret.
//
// TestResolvedSecretReuse_Equivalence pins, per case, the response (status, error
// code and message, the secret served) and every audit row and access-log row the
// request wrote for the secret. It uses nothing the change added, so it runs
// unchanged before and after the change: that is the before/after equivalence.
// TestResolvedSecretReuse_CrossReplicaRace races a share revoke (and a delete)
// committed on a second pool against reads on the first. TestResolvedSecretReuse_FetchCount
// is the red/green: statements issued by storage GetSecret per human metadata read.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
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

const rrPassword = "Qr7#Kp2$Lm5@Vn9!"

// rrReplica is one server process: its own *gorm.DB pool, LocalStorage (own
// read-path caches), core and router.
type rrReplica struct {
	c   *core.KeyorixCore
	db  *gorm.DB
	srv *httptest.Server

	mu        sync.Mutex
	counting  bool
	stmts     int
	getSecret int // statements issued from inside storage GetSecret
}

type rrWorld struct {
	a, b         *rrReplica // b is nil unless a second replica was asked for
	adminID      uint
	projectID    uint
	envA, envB   uint
	projectName  string
	envAName     string
	users        map[string]uint
	tokens       map[string]string
	machineToken string
	secretSeq    atomic.Int64
}

var rrSchemaSeq atomic.Int64

func rrStorageConfig(t *testing.T, backend string) (*config.Config, string) {
	t.Helper()
	switch backend {
	case "sqlite":
		return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxrr_")}}}, ""
	case "postgres":
		pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
		if pgDSN == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("perffix5_rr_%d_%d", os.Getpid(), rrSchemaSeq.Add(1))
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

// rrInStorageGetSecret reports whether the calling goroutine is inside
// LocalStorage.GetSecret (the GORM callback runs on the caller's goroutine).
func rrInStorageGetSecret() bool {
	pcs := make([]uintptr, 256)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, "store.(*LocalStorage).GetSecret") {
			return true
		}
		if !more {
			return false
		}
	}
}

func rrNewReplica(t *testing.T, st *store.LocalStorage) *rrReplica {
	t.Helper()
	r := &rrReplica{c: core.NewKeyorixCore(st), db: st.DB()}
	count := func(*gorm.DB) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.counting {
			return
		}
		r.stmts++
		if rrInStorageGetSecret() {
			r.getSecret++
		}
	}
	cb := r.db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("perffix5:count_q", count))
	require.NoError(t, cb.Row().After("gorm:row").Register("perffix5:count_row", count))
	require.NoError(t, cb.Raw().After("gorm:raw").Register("perffix5:count_raw", count))
	r.c.SetBootstrapToken("test-bootstrap-token")
	return r
}

// newRRWorld builds the fixture through the production storage factory (production
// read-path caches, cache_epoch trigger, role-permission cache). With twoReplicas
// (Postgres only) a second, independent pool and LocalStorage serve the same schema.
func newRRWorld(t *testing.T, backend string, twoReplicas bool) *rrWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg, pgTarget := rrStorageConfig(t, backend)
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	w := &rrWorld{a: rrNewReplica(t, ls), users: map[string]uint{}, tokens: map[string]string{}}
	if twoReplicas {
		require.NotEmpty(t, pgTarget, "two replicas need Postgres")
		db, oerr := gorm.Open(postgres.Open(pgTarget), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, oerr)
		sqlDB, derr := db.DB()
		require.NoError(t, derr)
		t.Cleanup(func() { _ = sqlDB.Close() })
		w.b = rrNewReplica(t, store.NewLocalStorage(db))
	}

	c, ctx := w.a.c, context.Background()
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "rradmin", Email: "rradmin@example.com", Password: rrPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "rradmin@example.com")
	require.NoError(t, err)
	w.adminID = admin.ID

	w.projectName, w.envAName = "rr-project", "rr-env-a"
	project, err := c.CreateProject(ctx, w.projectName, "resolved secret reuse")
	require.NoError(t, err)
	w.projectID = project.ID
	envA, err := c.CreateEnvironment(ctx, project.ID, w.envAName)
	require.NoError(t, err)
	envB, err := c.CreateEnvironment(ctx, project.ID, "rr-env-b")
	require.NoError(t, err)
	w.envA, w.envB = envA.ID, envB.ID
	other, err := c.CreateProject(ctx, "rr-other", "cross-project")
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	roleID := map[string]uint{}
	for _, r := range roles {
		roleID[r.Name] = r.ID
	}
	mk := func(name string) uint {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: rrPassword})
		require.NoError(t, uerr)
		w.users[name] = u.ID
		return u.ID
	}
	assign := func(user, role string, scope core.Scope) {
		require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk(user), roleID[role], scope, false))
	}
	// owner: project_developer at the project; creates and shares the secrets.
	assign("owner", "project_developer", core.Scope{ProjectID: project.ID})
	// dev: project_viewer at the project (secrets.read on every environment).
	assign("dev", "project_viewer", core.Scope{ProjectID: project.ID})
	// sharee / acluser: project members through a role on env B only, so their role
	// does not reach env-A secrets; a share / an ACL grant does.
	assign("sharee", "project_viewer", core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID})
	assign("acluser", "project_viewer", core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID})
	// outsider: project_developer in the other project only.
	assign("outsider", "project_developer", core.Scope{ProjectID: other.ID})
	// suspendee: project_viewer, suspended after signing in.
	assign("suspendee", "project_viewer", core.Scope{ProjectID: project.ID})
	// groupie: no role of their own; a member of a group holding project_viewer.
	groupie := mk("groupie")
	group, err := c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "rr-readers"})
	require.NoError(t, err)
	require.NoError(t, c.AddUserToGroup(ctx, admin.ID, false, groupie, group.ID, project.ID))
	require.NoError(t, c.AssignRoleToGroup(ctx, admin.ID, group.ID, roleID["project_viewer"], core.Scope{ProjectID: project.ID}, false))

	for _, name := range []string{"owner", "dev", "sharee", "acluser", "outsider", "suspendee", "groupie"} {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: name, Password: rrPassword})
		require.NoError(t, lerr, name)
		w.tokens[name] = sess.SessionToken
	}
	require.NoError(t, c.SuspendUser(ctx, admin.ID, w.users["suspendee"]))

	mi, err := c.CreateMachineIdentity(ctx, project.ID, "rr-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, project.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "rr-token"})
	require.NoError(t, err)
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID["project_developer"], core.Scope{ProjectID: project.ID}, admin.ID, false))
	w.machineToken = tok.PlainToken
	w.tokens["machine"] = tok.PlainToken

	w.a.srv = newSecretsMachineTestServer(t, w.a.c)
	t.Cleanup(w.a.srv.Close)
	if w.b != nil {
		w.b.srv = newSecretsMachineTestServer(t, w.b.c)
		t.Cleanup(w.b.srv.Close)
	}
	return w
}

// newSecret creates a fresh env-A secret owned by "owner", so cases never share state.
func (w *rrWorld) newSecret(t *testing.T) *models.SecretNode {
	t.Helper()
	n := w.secretSeq.Add(1)
	s, err := w.a.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: fmt.Sprintf("rr-secret-%d", n), Value: []byte(fmt.Sprintf("rr-value-%d", n)),
		ProjectID: w.projectID, EnvironmentID: w.envA, Type: "generic",
		CreatedBy: "owner", OwnerID: w.users["owner"],
	})
	require.NoError(t, err)
	return s
}

type rrOutcome struct {
	Status      int
	ErrCode     string
	ErrMsg      string
	ID          uint
	Name        string
	Description string
	ProjectID   uint
	Value       string
	// Audit rows and access-log rows this request added for the secret:
	// "event_type|user|project|success|actor" and "action|accessed_by".
	Audit  []string
	Access []string
}

type rrRequest struct {
	method string
	path   func(w *rrWorld, s *models.SecretNode) string
	body   string
}

var (
	rrGetMeta = rrRequest{method: http.MethodGet, path: func(_ *rrWorld, s *models.SecretNode) string {
		return fmt.Sprintf("/api/v1/secrets/%d", s.ID)
	}}
	rrPutDescription = rrRequest{method: http.MethodPut, path: func(_ *rrWorld, s *models.SecretNode) string {
		return fmt.Sprintf("/api/v1/secrets/%d", s.ID)
	}, body: `{"description":"rr-updated"}`}
	rrGetByRef = rrRequest{method: http.MethodGet, path: func(w *rrWorld, s *models.SecretNode) string {
		return fmt.Sprintf("/api/v1/secrets/value?ref=%s/%s/%s", w.projectName, w.envAName, s.Name)
	}}
)

func (r *rrReplica) rows(t *testing.T, secretID uint) (audit, access []string) {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, r.db.Where("secret_node_id = ?", secretID).Order("id").Find(&evs).Error)
	for _, ev := range evs {
		var uid, pid uint
		if ev.UserID != nil {
			uid = *ev.UserID
		}
		if ev.ProjectID != nil {
			pid = *ev.ProjectID
		}
		audit = append(audit, fmt.Sprintf("%s|%d|%d|%t|%s", ev.EventType, uid, pid, ev.Success != nil && *ev.Success, ev.ActorType))
	}
	var logs []models.SecretAccessLog
	require.NoError(t, r.db.Where("secret_node_id = ?", secretID).Order("id").Find(&logs).Error)
	for _, l := range logs {
		access = append(access, l.Action+"|"+l.AccessedBy)
	}
	return audit, access
}

// send issues the request and waits for the background audit writes it started.
func (r *rrReplica) send(t *testing.T, w *rrWorld, who string, req rrRequest, s *models.SecretNode) (int, []byte) {
	t.Helper()
	var body io.Reader
	if req.body != "" {
		body = bytes.NewBufferString(req.body)
	}
	hreq, err := http.NewRequestWithContext(context.Background(), req.method, r.srv.URL+req.path(w, s), body)
	require.NoError(t, err)
	hreq.Header.Set("Authorization", "Bearer "+w.tokens[who])
	if req.body != "" {
		hreq.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(hreq)
	require.NoError(t, err)
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	return resp.StatusCode, raw
}

func (r *rrReplica) do(t *testing.T, w *rrWorld, who string, req rrRequest, s *models.SecretNode) rrOutcome {
	t.Helper()
	beforeAudit, beforeAccess := r.rows(t, s.ID)
	status, raw := r.send(t, w, who, req, s)

	out := rrOutcome{Status: status}
	var env struct {
		Error   string          `json:"error"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &env), string(raw))
	out.ErrCode, out.ErrMsg = env.Error, env.Message
	if len(env.Data) > 0 && string(env.Data) != "null" {
		type wire struct {
			ID          uint   `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			ProjectID   uint   `json:"project_id"`
		}
		var data struct {
			wire
			Secret *wire  `json:"secret"`
			Value  string `json:"value"`
		}
		require.NoError(t, json.Unmarshal(env.Data, &data), string(env.Data))
		got := data.wire
		if data.Secret != nil {
			got = *data.Secret
		}
		out.ID, out.Name, out.Description, out.ProjectID, out.Value = got.ID, got.Name, got.Description, got.ProjectID, data.Value
	}
	afterAudit, afterAccess := r.rows(t, s.ID)
	out.Audit, out.Access = rrNewRows(beforeAudit, afterAudit), rrNewRows(beforeAccess, afterAccess)
	return out
}

// rrNewRows is after minus the before prefix, sorted (rows written by one request in
// background goroutines have no meaningful relative order).
func rrNewRows(before, after []string) []string {
	if len(after) <= len(before) {
		return nil
	}
	added := append([]string(nil), after[len(before):]...)
	sort.Strings(added)
	return added
}

func (w *rrWorld) metaOK(s *models.SecretNode, audit ...string) rrOutcome {
	return rrOutcome{Status: http.StatusOK, ID: s.ID, Name: s.Name, ProjectID: w.projectID, Audit: rrSorted(audit)}
}

func rrSorted(rows []string) []string {
	if len(rows) == 0 {
		return nil
	}
	out := append([]string(nil), rows...)
	sort.Strings(out)
	return out
}

func rrDenied(status int, code, msg string) rrOutcome {
	return rrOutcome{Status: status, ErrCode: code, ErrMsg: msg}
}

// elevated is the share_access_elevated row a share-made grant writes when performed.
func (w *rrWorld) elevated(user string) string {
	return fmt.Sprintf("%s|%d|%d|true|user", core.ShareAuditEventAccessElevated, w.users[user], w.projectID)
}

func TestResolvedSecretReuse_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { rrEquivalence(t, backend) })
	}
}

func rrEquivalence(t *testing.T, backend string) {
	w := newRRWorld(t, backend, false)
	c, ctx, r := w.a.c, context.Background(), w.a
	share := func(s *models.SecretNode, perm string) uint {
		rec, err := c.ShareSecret(ctx, &core.ShareSecretRequest{
			SecretID: s.ID, RecipientID: w.users["sharee"], Permission: perm, SharedBy: w.users["owner"],
		})
		require.NoError(t, err)
		return rec.ID
	}
	expireShare := func(id uint) {
		// Through Save(), so ShareRecord's BeforeSave hook runs (G1619).
		var rec models.ShareRecord
		require.NoError(t, r.db.First(&rec, id).Error)
		past := time.Now().Add(-time.Minute)
		rec.ExpiresAt = &past
		require.NoError(t, r.db.Save(&rec).Error)
	}
	forbidden := rrDenied(http.StatusForbidden, "Forbidden", "Insufficient permissions")

	cases := []struct {
		name  string
		who   string
		req   rrRequest
		setup func(s *models.SecretNode)
		want  func(s *models.SecretNode) rrOutcome
	}{
		{"owner", "owner", rrGetMeta, nil, func(s *models.SecretNode) rrOutcome { return w.metaOK(s) }},
		{"project role", "dev", rrGetMeta, nil, func(s *models.SecretNode) rrOutcome { return w.metaOK(s) }},
		{"group role", "groupie", rrGetMeta, nil, func(s *models.SecretNode) rrOutcome { return w.metaOK(s) }},
		{"read share", "sharee", rrGetMeta, func(s *models.SecretNode) { share(s, "read") },
			func(s *models.SecretNode) rrOutcome { return w.metaOK(s, w.elevated("sharee")) }},
		{"read share: write refused", "sharee", rrPutDescription, func(s *models.SecretNode) { share(s, "read") },
			func(*models.SecretNode) rrOutcome { return forbidden }},
		{"write share: read", "sharee", rrGetMeta, func(s *models.SecretNode) { share(s, "write") },
			func(s *models.SecretNode) rrOutcome { return w.metaOK(s, w.elevated("sharee")) }},
		{"write share: update", "sharee", rrPutDescription, func(s *models.SecretNode) { share(s, "write") },
			func(s *models.SecretNode) rrOutcome {
				return w.updated(s, w.users["sharee"], "user", "sharee", w.elevated("sharee"))
			}},
		{"revoked share", "sharee", rrGetMeta, func(s *models.SecretNode) {
			require.NoError(t, c.RevokeShare(ctx, share(s, "write"), w.users["owner"]))
		}, func(*models.SecretNode) rrOutcome { return forbidden }},
		{"expired share", "sharee", rrGetMeta, func(s *models.SecretNode) { expireShare(share(s, "write")) },
			func(*models.SecretNode) rrOutcome { return forbidden }},
		{"acl grant", "acluser", rrGetMeta, func(s *models.SecretNode) {
			require.NoError(t, c.GrantSecretACL(ctx, w.adminID, s.ID, w.users["acluser"], []string{"secrets.read"}))
		}, func(s *models.SecretNode) rrOutcome { return w.metaOK(s) }},
		{"no grant", "acluser", rrGetMeta, nil, func(*models.SecretNode) rrOutcome { return forbidden }},
		{"cross-project", "outsider", rrGetMeta, nil, func(*models.SecretNode) rrOutcome { return forbidden }},
		// The gate answers a deleted secret like an ungranted one (no existence oracle).
		{"deleted secret", "dev", rrGetMeta, func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
			func(*models.SecretNode) rrOutcome { return forbidden }},
		{"deleted secret: owner update", "owner", rrPutDescription, func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
			func(*models.SecretNode) rrOutcome { return forbidden }},
		{"suspended user", "suspendee", rrGetMeta, nil, func(*models.SecretNode) rrOutcome {
			return rrDenied(http.StatusUnauthorized, "Unauthorized", "Invalid or expired token")
		}},
		{"machine principal", "machine", rrGetMeta, nil, func(s *models.SecretNode) rrOutcome { return w.metaOK(s) }},
		{"machine principal: update", "machine", rrPutDescription, nil, func(s *models.SecretNode) rrOutcome {
			return w.updated(s, 0, "machine_identity", "rr-runner")
		}},
		{"expired secret", "dev", rrGetMeta, func(s *models.SecretNode) {
			// Through Save(), so SecretNode's BeforeSave hook runs (G1619).
			var row models.SecretNode
			require.NoError(t, r.db.First(&row, s.ID).Error)
			past := time.Now().Add(-time.Minute)
			row.Expiration = &past
			require.NoError(t, r.db.Save(&row).Error)
		}, func(*models.SecretNode) rrOutcome {
			return rrDenied(http.StatusConflict, "SecretExpired", "secret has expired; its value can no longer be read")
		}},
		{"schedule denies", "dev", rrGetMeta, func(s *models.SecretNode) {
			_, err := c.SetSecretSchedule(ctx, s.ID, rrNotTodayOrTomorrow(), 0, 24, "UTC")
			require.NoError(t, err)
		}, func(*models.SecretNode) rrOutcome {
			return rrDenied(http.StatusForbidden, "SecretAccessOutsideSchedule", core.ErrAccessOutsideSchedule.Error())
		}},
		// By reference: the gate resolves by name (ResolveSecretRef) and the decision
		// reuses that row.
		{"by ref: read share", "sharee", rrGetByRef, func(s *models.SecretNode) { share(s, "read") },
			func(s *models.SecretNode) rrOutcome { return w.valueOK(s, "sharee", w.elevated("sharee")) }},
		{"by ref: revoked share", "sharee", rrGetByRef, func(s *models.SecretNode) {
			require.NoError(t, c.RevokeShare(ctx, share(s, "read"), w.users["owner"]))
		}, func(*models.SecretNode) rrOutcome { return forbidden }},
		{"by ref: project role", "dev", rrGetByRef, nil, func(s *models.SecretNode) rrOutcome { return w.valueOK(s, "dev") }},
		{"by ref: cross-project", "outsider", rrGetByRef, nil, func(*models.SecretNode) rrOutcome { return forbidden }},
		{"by ref: deleted secret", "dev", rrGetByRef, func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
			func(*models.SecretNode) rrOutcome { return forbidden }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := w.newSecret(t)
			// Warm every read-path cache first, so a stale cache entry would show as a
			// wrong outcome below.
			require.Equal(t, http.StatusOK, r.do(t, w, "owner", rrGetMeta, s).Status)
			if tc.setup != nil {
				tc.setup(s)
			}
			assert.Equal(t, tc.want(s), r.do(t, w, tc.who, tc.req, s))
		})
	}
}

// updated is the outcome of a successful PUT /secrets/{id} (the response carries the
// secret as the update returned it).
func (w *rrWorld) updated(s *models.SecretNode, uid uint, actor, accessedBy string, extraAudit ...string) rrOutcome {
	o := w.metaOK(s, append([]string{fmt.Sprintf("secret.updated|%d|%d|true|%s", uid, w.projectID, actor)}, extraAudit...)...)
	o.ErrMsg = "Secret updated successfully"
	o.Access = []string{"update|" + accessedBy}
	return o
}

// valueOK is the outcome of a successful by-reference value read.
func (w *rrWorld) valueOK(s *models.SecretNode, user string, extraAudit ...string) rrOutcome {
	o := w.metaOK(s, append([]string{fmt.Sprintf("secret.read|%d|%d|true|user", w.users[user], w.projectID)}, extraAudit...)...)
	o.Value = strings.Replace(s.Name, "rr-secret-", "rr-value-", 1)
	o.Access = []string{"read|" + user}
	return o
}

func rrNotTodayOrTomorrow() string {
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
			days = append(days, fmt.Sprint(d))
		}
	}
	return strings.Join(days, ",")
}

// TestResolvedSecretReuse_CrossReplicaRace: replica A serves metadata reads by a
// share holder in a loop while replica B (own pool, own caches, same Postgres schema)
// revokes the share, or deletes the secret. A read that finished before B's write
// started is allowed; a read that started after B's write committed is refused; a
// read overlapping it is one of the outcomes either side gives (and nothing else: no
// 500, no partial audit). Every allowed read wrote exactly one share_access_elevated
// row, and a refused one none.
func TestResolvedSecretReuse_CrossReplicaRace(t *testing.T) {
	w := newRRWorld(t, "postgres", true)
	a, b, ctx := w.a, w.b, context.Background()
	forbidden := rrDenied(http.StatusForbidden, "Forbidden", "Insufficient permissions")
	// The handler's own read check refusing after the gate allowed the request.
	handlerRefused := rrDenied(http.StatusForbidden, "Forbidden", "Access denied")

	type sample struct {
		start, end time.Time
		out        rrOutcome
	}
	// own keeps the rows the reader itself wrote (B's revoke/delete writes its own
	// audit row for the same secret, possibly while a read is in flight).
	sharee := fmt.Sprintf("|%d|", w.users["sharee"])
	own := func(o rrOutcome) rrOutcome {
		var kept []string
		for _, row := range o.Audit {
			if strings.Contains(row, sharee) {
				kept = append(kept, row)
			}
		}
		o.Audit = kept
		return o
	}
	for _, race := range []struct {
		name string
		// write commits the change on B; extra lists outcomes, besides allowed and
		// forbidden, that a read overlapping the write may give.
		write func(s *models.SecretNode, shareID uint) error
		extra []rrOutcome
	}{
		// A revoke landing after the gate passed and before the handler's own read
		// check: the handler refuses (seen on main before this change too).
		{"share revoke", func(_ *models.SecretNode, shareID uint) error {
			return b.c.RevokeShare(ctx, shareID, w.users["owner"])
		}, []rrOutcome{handlerRefused}},
		// A delete landing after the gate passed: the handler's own read check
		// refuses, or does not find the secret (404).
		{"secret delete", func(s *models.SecretNode, _ uint) error {
			return b.c.DeleteSecret(ctx, s.ID)
		}, []rrOutcome{handlerRefused, rrDenied(http.StatusNotFound, "NotFound", "Secret not found")}},
	} {
		t.Run(race.name, func(t *testing.T) {
			for round := 0; round < 3; round++ {
				s := w.newSecret(t)
				rec, err := a.c.ShareSecret(ctx, &core.ShareSecretRequest{
					SecretID: s.ID, RecipientID: w.users["sharee"], Permission: "read", SharedBy: w.users["owner"],
				})
				require.NoError(t, err)
				allowed := w.metaOK(s, w.elevated("sharee"))
				require.Equal(t, allowed, a.do(t, w, "sharee", rrGetMeta, s), "warm read on A")

				// B writes from a goroutine once A has completed a few reads; A reads on
				// the test goroutine until a few reads have started after B's write
				// committed. Counts, not sleeps, so a loaded machine cannot starve
				// either side.
				const margin = 5
				var (
					wStart, wEnd time.Time
					wErr         error
					completed    atomic.Int64
					done         = make(chan struct{})
				)
				go func() {
					defer close(done)
					for completed.Load() < margin {
						time.Sleep(time.Millisecond)
					}
					wStart = time.Now()
					wErr = race.write(s, rec.ID)
					wEnd = time.Now()
				}()
				var samples []sample
				writeDone := false
				for afterWrite := 0; afterWrite < margin; {
					st := time.Now()
					out := own(a.do(t, w, "sharee", rrGetMeta, s))
					samples = append(samples, sample{st, time.Now(), out})
					completed.Add(1)
					if !writeDone {
						select {
						case <-done:
							writeDone = true
						default:
						}
					}
					if writeDone && st.After(wEnd) {
						afterWrite++
					}
				}
				require.NoError(t, wErr)

				valid := append([]rrOutcome{allowed, forbidden}, race.extra...)
				var before, after int
				overlap := map[int]int{} // status -> reads
				for i, sm := range samples {
					switch {
					case sm.end.Before(wStart):
						before++
						assert.Equal(t, allowed, sm.out, "round %d read %d finished before the write", round, i)
					case sm.start.After(wEnd):
						after++
						assert.Equal(t, forbidden, sm.out, "round %d read %d started after the write committed", round, i)
					default:
						overlap[sm.out.Status]++
						assert.Contains(t, valid, sm.out, "round %d read %d overlapped the write", round, i)
					}
				}
				t.Logf("round %d: %d reads before the write, %d after, overlapping by status %v", round, before, after, overlap)
				require.Positive(t, before, "round %d: no read finished before the write", round)
				require.Positive(t, after, "round %d: no read started after the write", round)
			}
		})
	}
}

// TestResolvedSecretReuse_FetchCount is the red/green for the change: statements
// issued by storage GetSecret during one human metadata read. Before: the gate's
// resolution, AuthorizeSecretAction's re-fetch, checkSecretPermission's fetch and
// GetSecretWithPermissionCheck's re-fetch (4, one node-stamp statement each on warm
// caches). After: the gate's resolution and checkSecretPermission's fetch (2).
func TestResolvedSecretReuse_FetchCount(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newRRWorld(t, backend, false)
			s, r := w.newSecret(t), w.a
			count := func(who string, req rrRequest) (int, int) {
				st, _ := r.send(t, w, who, req, s)
				require.Equal(t, http.StatusOK, st, "warm")
				r.mu.Lock()
				r.counting, r.stmts, r.getSecret = true, 0, 0
				r.mu.Unlock()
				st, _ = r.send(t, w, who, req, s)
				r.mu.Lock()
				r.counting = false
				stmts, fetch := r.stmts, r.getSecret
				r.mu.Unlock()
				require.Equal(t, http.StatusOK, st)
				return stmts, fetch
			}
			stmts, fetch := count("dev", rrGetMeta)
			t.Logf("%s: human metadata read: %d read statements (GORM), %d of them in storage GetSecret", backend, stmts, fetch)
			assert.Equal(t, 2, fetch, "a human metadata read fetches the secret twice: the gate's resolution and the core read check's")
			_, mfetch := count("machine", rrGetMeta)
			assert.Equal(t, 1, mfetch, "a machine metadata read fetches the secret once (unchanged)")
		})
	}
}
