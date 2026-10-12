package services

// PERF-FIX-5 (collapses C2 + C3, gRPC half): authorizeSecretScoped resolves the
// secret and hands it to core.AuthorizeSecretPrincipalForSecretAction, whose human
// branch fetched it again (C2); GetSecretWithPermissionCheck fetched it once in its
// read check and again to return it (C3). This test pins the outcome of GetSecret and
// UpdateSecret per case (gRPC status, the secret served, the audit rows written) and
// runs unchanged before and after the change; the GetSecret statement count is the
// red/green. Calls go through ShareElevationAuditInterceptor, as in the server chain.
// A suspended user is refused by the auth interceptor before any of this runs (not in
// this harness; the REST test covers it end to end).

import (
	"context"
	"fmt"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
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
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const grrPassword = "Qr7#Kp2$Lm5@Vn9!"

var grrSchemaSeq atomic.Int64

type grrWorld struct {
	c         *core.KeyorixCore
	db        *gorm.DB
	svc       *SecretGRPCService
	adminID   uint
	projectID uint
	envA      uint
	users     map[string]uint
	machineID uint
	seq       atomic.Int64

	mu        sync.Mutex
	counting  bool
	getSecret int // statements issued from inside storage GetSecret
}

func grrInStorageGetSecret() bool {
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

func newGRRWorld(t *testing.T, backend string) *grrWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	var cfg *config.Config
	switch backend {
	case "sqlite":
		cfg = &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxgrr_")}}}
	case "postgres":
		pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
		if pgDSN == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("perffix5_grr_%d_%d", os.Getpid(), grrSchemaSeq.Add(1))
		admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
		cfg = &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgdsn.PGSearchPathDSN(pgDSN, schema)}}}
	}
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	w := &grrWorld{c: core.NewKeyorixCore(st), db: ls.DB(), users: map[string]uint{}}
	w.svc = NewSecretService(w.c)
	count := func(*gorm.DB) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.counting && grrInStorageGetSecret() {
			w.getSecret++
		}
	}
	cb := w.db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("perffix5:grr_q", count))
	require.NoError(t, cb.Raw().After("gorm:raw").Register("perffix5:grr_raw", count))
	require.NoError(t, cb.Row().After("gorm:row").Register("perffix5:grr_row", count))

	c, ctx := w.c, context.Background()
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "grradmin", Email: "grradmin@example.com", Password: grrPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "grradmin@example.com")
	require.NoError(t, err)
	w.adminID = admin.ID
	project, err := c.CreateProject(ctx, "grr-project", "")
	require.NoError(t, err)
	w.projectID = project.ID
	envA, err := c.CreateEnvironment(ctx, project.ID, "grr-env-a")
	require.NoError(t, err)
	envB, err := c.CreateEnvironment(ctx, project.ID, "grr-env-b")
	require.NoError(t, err)
	w.envA = envA.ID
	other, err := c.CreateProject(ctx, "grr-other", "")
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	roleID := map[string]uint{}
	for _, r := range roles {
		roleID[r.Name] = r.ID
	}
	mk := func(name string) uint {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: grrPassword})
		require.NoError(t, uerr)
		w.users[name] = u.ID
		return u.ID
	}
	grant := func(name, role string, scope core.Scope) {
		require.NoError(t, c.AssignUserRole(ctx, admin.ID, mk(name), roleID[role], scope, false))
	}
	grant("owner", "project_developer", core.Scope{ProjectID: project.ID})
	grant("dev", "project_viewer", core.Scope{ProjectID: project.ID})
	grant("sharee", "project_viewer", core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID})
	grant("outsider", "project_developer", core.Scope{ProjectID: other.ID})
	groupie := mk("groupie")
	group, err := c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "grr-readers"})
	require.NoError(t, err)
	require.NoError(t, c.AddUserToGroup(ctx, admin.ID, false, groupie, group.ID, project.ID))
	require.NoError(t, c.AssignRoleToGroup(ctx, admin.ID, group.ID, roleID["project_viewer"], core.Scope{ProjectID: project.ID}, false))

	mi, err := c.CreateMachineIdentity(ctx, project.ID, "grr-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID["project_developer"], core.Scope{ProjectID: project.ID}, admin.ID, false))
	w.machineID = mi.ID
	return w
}

func (w *grrWorld) newSecret(t *testing.T) *models.SecretNode {
	t.Helper()
	n := w.seq.Add(1)
	s, err := w.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: fmt.Sprintf("grr-secret-%d", n), Value: []byte(fmt.Sprintf("grr-value-%d", n)),
		ProjectID: w.projectID, EnvironmentID: w.envA, Type: "generic",
		CreatedBy: "owner", OwnerID: w.users["owner"],
	})
	require.NoError(t, err)
	return s
}

// principalCtx is what the gRPC auth interceptor hands the service.
func (w *grrWorld) principalCtx(name string) context.Context {
	if name == "machine" {
		uc := &interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: w.machineID, Username: "grr-runner"}
		ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), uc)
		return core.WithMachineActor(core.WithActorType(ctx, core.ActorTypeMachine), w.machineID)
	}
	uc := &interceptors.UserContext{UserID: w.users[name], Username: name}
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(), uc)
}

type grrOutcome struct {
	Code  string
	Msg   string
	ID    uint32
	Name  string
	Audit []string // audit rows the call added for the secret: "event_type|user|project|success"
}

func (w *grrWorld) audit(t *testing.T, secretID uint) []string {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, w.db.Where("secret_node_id = ?", secretID).Order("id").Find(&evs).Error)
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		var uid, pid uint
		if ev.UserID != nil {
			uid = *ev.UserID
		}
		if ev.ProjectID != nil {
			pid = *ev.ProjectID
		}
		out = append(out, fmt.Sprintf("%s|%d|%d|%t", ev.EventType, uid, pid, ev.Success != nil && *ev.Success))
	}
	return out
}

// call runs one RPC through ShareElevationAuditInterceptor, as the server chain does.
func (w *grrWorld) call(t *testing.T, who string, s *models.SecretNode, rpc string) grrOutcome {
	t.Helper()
	before := w.audit(t, s.ID)
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		switch rpc {
		case "GetSecret":
			return w.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: uint32(s.ID)})
		case "UpdateSecret":
			return w.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: uint32(s.ID), Metadata: map[string]string{"k": "v"}})
		}
		return nil, fmt.Errorf("unknown rpc %q", rpc)
	}
	resp, err := interceptors.ShareElevationAuditInterceptor(w.c)(w.principalCtx(who), nil, &grpc.UnaryServerInfo{FullMethod: rpc}, handler)
	DrainBackgroundGoroutines() // the service's async audit writes (goSafe)
	core.DrainBackgroundGoroutines()
	after := w.audit(t, s.ID)
	out := grrOutcome{}
	if len(after) > len(before) {
		out.Audit = append(out.Audit, after[len(before):]...)
		sort.Strings(out.Audit)
	}
	if err != nil {
		st, _ := status.FromError(err)
		out.Code, out.Msg = st.Code().String(), st.Message()
		return out
	}
	sec, ok := resp.(*pb.Secret)
	require.True(t, ok, "%T", resp)
	out.Code, out.ID, out.Name = "OK", sec.GetId(), sec.GetName()
	return out
}

func TestGRPCResolvedSecretReuse_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newGRRWorld(t, backend)
			c, ctx := w.c, context.Background()
			share := func(s *models.SecretNode, perm string) uint {
				rec, err := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: s.ID, RecipientID: w.users["sharee"], Permission: perm, SharedBy: w.users["owner"]})
				require.NoError(t, err)
				return rec.ID
			}
			ok := func(audit ...string) func(*models.SecretNode) grrOutcome {
				return func(s *models.SecretNode) grrOutcome {
					o := grrOutcome{Code: "OK", ID: uint32(s.ID), Name: s.Name}
					if len(audit) > 0 {
						o.Audit = append([]string(nil), audit...)
						sort.Strings(o.Audit)
					}
					return o
				}
			}
			denied := func(code, msg string) func(*models.SecretNode) grrOutcome {
				return func(*models.SecretNode) grrOutcome { return grrOutcome{Code: code, Msg: msg} }
			}
			elevated := fmt.Sprintf("%s|%d|%d|true", core.ShareAuditEventAccessElevated, w.users["sharee"], w.projectID)
			updated := func(uid uint) string { return fmt.Sprintf("secret.updated|%d|%d|true", uid, w.projectID) }
			insufficient := denied("PermissionDenied", "insufficient permissions")
			cases := []struct {
				name  string
				who   string
				rpc   string
				setup func(s *models.SecretNode)
				want  func(s *models.SecretNode) grrOutcome
			}{
				{"owner", "owner", "GetSecret", nil, ok()},
				{"project role", "dev", "GetSecret", nil, ok()},
				{"group role", "groupie", "GetSecret", nil, ok()},
				{"read share", "sharee", "GetSecret", func(s *models.SecretNode) { share(s, "read") }, ok(elevated)},
				{"read share: update refused", "sharee", "UpdateSecret", func(s *models.SecretNode) { share(s, "read") }, insufficient},
				{"write share: read", "sharee", "GetSecret", func(s *models.SecretNode) { share(s, "write") }, ok(elevated)},
				{"write share: update", "sharee", "UpdateSecret", func(s *models.SecretNode) { share(s, "write") }, ok(elevated, updated(w.users["sharee"]))},
				{"revoked share", "sharee", "GetSecret", func(s *models.SecretNode) {
					require.NoError(t, c.RevokeShare(ctx, share(s, "write"), w.users["owner"]))
				}, insufficient},
				{"expired share", "sharee", "GetSecret", func(s *models.SecretNode) {
					id := share(s, "write")
					// Through Save(), so ShareRecord's BeforeSave hook runs (G1619).
					var rec models.ShareRecord
					require.NoError(t, w.db.First(&rec, id).Error)
					past := time.Now().Add(-time.Minute)
					rec.ExpiresAt = &past
					require.NoError(t, w.db.Save(&rec).Error)
				}, insufficient},
				{"cross-project", "outsider", "GetSecret", nil, insufficient},
				{"deleted secret", "dev", "GetSecret", func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) }, insufficient},
				{"machine principal", "machine", "GetSecret", nil, ok()},
				{"machine principal: update", "machine", "UpdateSecret", nil, ok(updated(0))},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					s := w.newSecret(t)
					require.Equal(t, "OK", w.call(t, "owner", s, "GetSecret").Code, "warm read")
					if tc.setup != nil {
						tc.setup(s)
					}
					assert.Equal(t, tc.want(s), w.call(t, tc.who, s, tc.rpc))
				})
			}

			// Red/green: before, a human GetSecret fetched the secret four times
			// (authorizeSecretScoped, AuthorizeSecretAction, checkSecretPermission,
			// GetSecretWithPermissionCheck's GetSecret); after, twice.
			t.Run("fetch count", func(t *testing.T) {
				s := w.newSecret(t)
				fetches := func(who string) int {
					require.Equal(t, "OK", w.call(t, who, s, "GetSecret").Code)
					w.mu.Lock()
					w.counting, w.getSecret = true, 0
					w.mu.Unlock()
					require.Equal(t, "OK", w.call(t, who, s, "GetSecret").Code)
					w.mu.Lock()
					defer w.mu.Unlock()
					w.counting = false
					return w.getSecret
				}
				assert.Equal(t, 2, fetches("dev"), "human GetSecret: the scoped gate's resolution and the core read check's")
				assert.Equal(t, 2, fetches("machine"), "machine GetSecret: unchanged (gate resolution + core.GetSecret)")
			})
		})
	}
}
