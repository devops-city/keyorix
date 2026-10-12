package services

// PERF-FIX-3 (collapse C1, gRPC half): GetSecretValue for a human evaluated the
// same read-permission check twice (GetSecretWithPermissionCheck, then
// GetSecretValueWithPermissionCheck) and fetched the secret again in between; for a
// machine it fetched the secret twice (GetSecret, then GetSecretValue by id). Both
// now reuse the first resolution. This test pins the outcome per case — gRPC status,
// value, name and the audit/access-log rows — and passes unchanged before and after
// the change (it uses nothing the change added); the share-lookup count is the
// red/green.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const gvoPassword = "Qr7#Kp2$Lm5@Vn9!"

var gvoSchemaSeq atomic.Int64

type gvoWorld struct {
	c         *core.KeyorixCore
	db        *gorm.DB
	svc       *SecretGRPCService
	adminID   uint
	projectID uint
	envA      uint
	users     map[string]uint
	machineID uint
	seq       atomic.Int64

	mu          sync.Mutex
	counting    bool
	shareLookup int
}

func newGVOWorld(t *testing.T, backend string) *gvoWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	var cfg *config.Config
	switch backend {
	case "sqlite":
		cfg = &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxgvo_")}}}
	case "postgres":
		pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
		if pgDSN == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("perffix3_gvo_%d_%d", os.Getpid(), gvoSchemaSeq.Add(1))
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
	w := &gvoWorld{c: core.NewKeyorixCore(st), db: ls.DB(), users: map[string]uint{}}
	w.svc = NewSecretService(w.c)
	require.NoError(t, w.db.Callback().Query().After("gorm:query").Register("perffix3:gvo_share", func(db *gorm.DB) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.counting && strings.Contains(db.Statement.SQL.String(), "share_records") {
			w.shareLookup++
		}
	}))

	c, ctx := w.c, context.Background()
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "gvoadmin", Email: "gvoadmin@example.com", Password: gvoPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "gvoadmin@example.com")
	require.NoError(t, err)
	w.adminID = admin.ID
	project, err := c.CreateProject(ctx, "gvo-project", "")
	require.NoError(t, err)
	w.projectID = project.ID
	envA, err := c.CreateEnvironment(ctx, project.ID, "gvo-env-a")
	require.NoError(t, err)
	envB, err := c.CreateEnvironment(ctx, project.ID, "gvo-env-b")
	require.NoError(t, err)
	w.envA = envA.ID
	other, err := c.CreateProject(ctx, "gvo-other", "")
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	roleID := map[string]uint{}
	for _, r := range roles {
		roleID[r.Name] = r.ID
	}
	grant := func(name, role string, scope core.Scope) {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: gvoPassword})
		require.NoError(t, uerr)
		w.users[name] = u.ID
		require.NoError(t, c.AssignUserRole(ctx, admin.ID, u.ID, roleID[role], scope, false))
	}
	grant("owner", "project_developer", core.Scope{ProjectID: project.ID})
	grant("dev", "project_viewer", core.Scope{ProjectID: project.ID})
	grant("sharee", "project_viewer", core.Scope{ProjectID: project.ID, EnvironmentID: envB.ID})
	grant("outsider", "project_developer", core.Scope{ProjectID: other.ID})

	mi, err := c.CreateMachineIdentity(ctx, project.ID, "gvo-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID["project_developer"], core.Scope{ProjectID: project.ID}, admin.ID, false))
	w.machineID = mi.ID
	return w
}

func (w *gvoWorld) newSecret(t *testing.T) *models.SecretNode {
	t.Helper()
	n := w.seq.Add(1)
	s, err := w.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: fmt.Sprintf("gvo-secret-%d", n), Value: []byte(fmt.Sprintf("gvo-value-%d", n)),
		ProjectID: w.projectID, EnvironmentID: w.envA, Type: "generic",
		CreatedBy: "owner", OwnerID: w.users["owner"],
	})
	require.NoError(t, err)
	return s
}

// principalCtx is what the gRPC auth interceptor hands the service.
func (w *gvoWorld) principalCtx(name string) context.Context {
	if name == "machine" {
		uc := &interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: w.machineID, Username: "gvo-runner"}
		ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), uc)
		return core.WithMachineActor(core.WithActorType(ctx, core.ActorTypeMachine), w.machineID)
	}
	uc := &interceptors.UserContext{UserID: w.users[name], Username: name}
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(), uc)
}

type gvoOutcome struct {
	Code       string
	Msg        string
	Name       string
	Value      string
	ReadEvents int
	ReadLogs   int
}

func (w *gvoWorld) rows(t *testing.T, secretID uint) (int64, int64) {
	t.Helper()
	var ev, lg int64
	require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("secret_node_id = ? AND event_type = ?", secretID, "secret.read").Count(&ev).Error)
	require.NoError(t, w.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ? AND action = ?", secretID, "read").Count(&lg).Error)
	return ev, lg
}

func (w *gvoWorld) read(t *testing.T, who string, secretID uint) gvoOutcome {
	t.Helper()
	ev0, lg0 := w.rows(t, secretID)
	resp, err := w.svc.GetSecretValue(w.principalCtx(who), &pb.GetSecretRequest{Id: uint32(secretID)})
	core.DrainBackgroundGoroutines()
	ev1, lg1 := w.rows(t, secretID)
	out := gvoOutcome{ReadEvents: int(ev1 - ev0), ReadLogs: int(lg1 - lg0)}
	if err != nil {
		st, _ := status.FromError(err)
		out.Code, out.Msg = st.Code().String(), st.Message()
		return out
	}
	out.Code, out.Name, out.Value = "OK", resp.GetName(), resp.GetValue()
	return out
}

func gvoAllowed(s *models.SecretNode) gvoOutcome {
	return gvoOutcome{Code: "OK", Name: s.Name, Value: strings.Replace(s.Name, "gvo-secret-", "gvo-value-", 1), ReadEvents: 1, ReadLogs: 1}
}

func gvoNotTodayOrTomorrow() string {
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

func TestGRPCValueReadAuthorizeOnce_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newGVOWorld(t, backend)
			c, ctx := w.c, context.Background()
			share := func(s *models.SecretNode) uint {
				rec, err := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: s.ID, RecipientID: w.users["sharee"], Permission: "read", SharedBy: w.users["owner"]})
				require.NoError(t, err)
				return rec.ID
			}
			denied := func(code, msg string) func(*models.SecretNode) gvoOutcome {
				return func(*models.SecretNode) gvoOutcome { return gvoOutcome{Code: code, Msg: msg} }
			}
			cases := []struct {
				name  string
				who   string
				setup func(s *models.SecretNode)
				want  func(s *models.SecretNode) gvoOutcome
			}{
				{"role grant", "dev", nil, gvoAllowed},
				{"live owner", "owner", nil, gvoAllowed},
				{"machine role grant", "machine", nil, gvoAllowed},
				{"read share", "sharee", func(s *models.SecretNode) { share(s) }, gvoAllowed},
				{"revoked share", "sharee", func(s *models.SecretNode) { require.NoError(t, c.RevokeShare(ctx, share(s), w.users["owner"])) },
					denied("PermissionDenied", "insufficient permissions")},
				{"cross-project", "outsider", nil, denied("PermissionDenied", "insufficient permissions")},
				{"deleted", "dev", func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
					denied("PermissionDenied", "insufficient permissions")},
				{"deleted (machine)", "machine", func(s *models.SecretNode) { require.NoError(t, c.DeleteSecret(ctx, s.ID)) },
					denied("PermissionDenied", "insufficient permissions")},
				{"suspended", "dev", func(s *models.SecretNode) {
					_, err := c.SuspendSecret(ctx, s.ID, w.adminID, "perf-fix-3")
					require.NoError(t, err)
				}, denied("Internal", "secret operation failed")},
				{"suspended (machine)", "machine", func(s *models.SecretNode) {
					_, err := c.SuspendSecret(ctx, s.ID, w.adminID, "perf-fix-3")
					require.NoError(t, err)
				}, denied("Internal", "secret operation failed")},
				{"expired", "dev", func(s *models.SecretNode) {
					// Through Save(), so SecretNode's BeforeSave hook runs (G1619).
					var row models.SecretNode
					require.NoError(t, w.db.First(&row, s.ID).Error)
					past := time.Now().Add(-time.Minute)
					row.Expiration = &past
					require.NoError(t, w.db.Save(&row).Error)
				}, denied("Internal", "secret operation failed")},
				{"schedule denies", "dev", func(s *models.SecretNode) {
					_, err := c.SetSecretSchedule(ctx, s.ID, gvoNotTodayOrTomorrow(), 0, 24, "UTC")
					require.NoError(t, err)
				}, denied("Internal", "secret operation failed")},
				{"schedule denies (machine)", "machine", func(s *models.SecretNode) {
					_, err := c.SetSecretSchedule(ctx, s.ID, gvoNotTodayOrTomorrow(), 0, 24, "UTC")
					require.NoError(t, err)
				}, denied("Internal", "secret operation failed")},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					s := w.newSecret(t)
					require.Equal(t, "OK", w.read(t, "owner", s.ID).Code, "warm read")
					if tc.setup != nil {
						tc.setup(s)
					}
					assert.Equal(t, tc.want(s), w.read(t, tc.who, s.ID))
				})
			}
			t.Run("max reads exhausted", func(t *testing.T) {
				s := w.newSecret(t)
				one := 1
				_, err := c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: s.ID, MaxReads: &one, UpdatedBy: "owner"})
				require.NoError(t, err)
				assert.Equal(t, gvoAllowed(s), w.read(t, "dev", s.ID))
				assert.Equal(t, gvoOutcome{Code: "Internal", Msg: "secret operation failed"}, w.read(t, "dev", s.ID))
			})

			t.Run("permission check runs once", func(t *testing.T) {
				s := w.newSecret(t)
				require.Equal(t, "OK", w.read(t, "dev", s.ID).Code)
				w.mu.Lock()
				w.counting, w.shareLookup = true, 0
				w.mu.Unlock()
				require.Equal(t, "OK", w.read(t, "dev", s.ID).Code)
				w.mu.Lock()
				w.counting = false
				n := w.shareLookup
				w.mu.Unlock()
				assert.Equal(t, 1, n, "CheckSecretPermission must run once per GetSecretValue")
			})
		})
	}
}
