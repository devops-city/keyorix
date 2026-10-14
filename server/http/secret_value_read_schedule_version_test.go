package http

// secret_value_read_schedule_version_test.go — PERF-FIX-4 (collapse C5 of
// SESSION-PERF-FIX-3's plan).
//
// A latest-version value read ran two statements on the same secret after its
// guards: the access-schedule read (GetSecretAccessSchedule) and the
// latest-version generation probe (GetLatestSecretVersion ->
// liveVersionsGeneration). They are now one statement
// (storage.GetSecretScheduleAndLatestVersion).
//
// TestValueReadScheduleVersion_Equivalence is the behaviour pin: for every case
// below it records, for every value-read path (REST include_value, REST ?ref=,
// gRPC GetSecretValue) and both principal kinds (machine token = the bench path,
// human session), the status and the disclosed value or error body. It uses
// nothing the change added, and it passes unchanged on the code before the
// change and after it: that is the before/after equivalence.
// TestValueReadScheduleVersion_CrossReplica does the same across two Postgres
// replicas (two pools, two caches): a schedule change or a new/deleted version
// written through one is seen by the other's very next read.
// TestValueReadScheduleVersion_ConcurrentVersionWrites reads while versions are
// being written. TestValueReadScheduleVersion_OneStatement is the red/green:
// before, a warm machine value read issued 2 statements on
// secret_access_schedules/secret_versions; after, 1.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
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
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const svPassword = "Qr7#Kp2$Lm5@Vn9!"

var svSchemaSeq atomic.Int64

// svReplica is one server process: its own *gorm.DB pool, its own LocalStorage
// (own read-path caches), core, router and gRPC server.
type svReplica struct {
	c      *core.KeyorixCore
	db     *gorm.DB
	router http.Handler
	grpc   pb.SecretServiceClient

	mu       sync.Mutex
	counting bool
	stmts    []string
}

type svWorld struct {
	a, b    *svReplica // b is nil unless two replicas were asked for
	c       *svReplica // nil unless three replicas were asked for
	backend string
	adminID uint
	projID  uint
	envID   uint
	tokens  map[string]string // "machine" | "human" -> bearer token
	seq     atomic.Int64
}

func svStorageConfig(t *testing.T, backend string) *config.Config {
	t.Helper()
	switch backend {
	case "sqlite":
		return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxsv_")}}}
	case "postgres":
		pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
		if pgDSN == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("perffix4_sv_%d_%d", os.Getpid(), svSchemaSeq.Add(1))
		admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		if sqlDB, err := admin.DB(); err == nil {
			t.Cleanup(func() { _ = sqlDB.Close() }) // runs after the DROP below
		}
		t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
		return &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgdsn.PGSearchPathDSN(pgDSN, schema)}}}
	}
	t.Fatalf("unknown backend %q", backend)
	return nil
}

// newSVReplica builds storage through the PRODUCTION factory, so the read-path
// caches, the cache_epoch trigger and the role-permission cache are all live.
func newSVReplica(t *testing.T, cfg *config.Config) *svReplica {
	t.Helper()
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	r := &svReplica{c: core.NewKeyorixCore(st), db: ls.DB()}
	if sqlDB, err := r.db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	record := func(db *gorm.DB) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.counting {
			r.stmts = append(r.stmts, db.Statement.SQL.String())
		}
	}
	cb := r.db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("perffix4:q", record))
	require.NoError(t, cb.Row().After("gorm:row").Register("perffix4:row", record))
	require.NoError(t, cb.Raw().After("gorm:raw").Register("perffix4:raw", record))
	require.NoError(t, cb.Create().After("gorm:create").Register("perffix4:c", record))
	require.NoError(t, cb.Update().After("gorm:update").Register("perffix4:u", record))
	require.NoError(t, cb.Delete().After("gorm:delete").Register("perffix4:d", record))

	router, err := NewRouter(&config.Config{}, r.c)
	require.NoError(t, err)
	r.router = router
	srv, err := keyorixgrpc.NewServer(&config.Config{}, r.c)
	require.NoError(t, err)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	r.grpc = pb.NewSecretServiceClient(conn)
	return r
}

func newSVWorld(t *testing.T, backend string, replicas int) *svWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := svStorageConfig(t, backend)
	w := &svWorld{backend: backend, a: newSVReplica(t, cfg)}
	if replicas >= 2 {
		w.b = newSVReplica(t, cfg)
	}
	if replicas >= 3 {
		w.c = newSVReplica(t, cfg)
	}
	c, db, ctx := w.a.c, w.a.db, context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "svadmin", Email: "svadmin@example.com", Password: svPassword, Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "svadmin", Password: svPassword})
	require.NoError(t, err)
	var admin models.User
	require.NoError(t, db.Where("username = ?", "svadmin").First(&admin).Error)
	w.adminID = admin.ID

	proj, err := c.CreateProject(ctx, "svproj", "")
	require.NoError(t, err)
	w.projID = proj.ID
	var env models.Environment
	if e := db.Where("project_id = ? AND name = ?", proj.ID, "prod").First(&env).Error; e != nil {
		env = models.Environment{Name: "prod", ProjectID: proj.ID}
		require.NoError(t, db.Create(&env).Error)
	}
	w.envID = env.ID

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		require.NoError(t, db.Create(&perm).Error)
	}
	role := models.Role{Name: "sv-reader", NameFolded: "sv-reader"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	m, err := c.CreateMachineIdentity(ctx, proj.ID, "sv-bot", "service", "", "", admin.ID, 0)
	require.NoError(t, err)
	require.NoError(t, c.AssignMachineRole(ctx, m.ID, role.ID, core.Scope{ProjectID: proj.ID}, admin.ID, false))
	mtok, err := c.IssueMachineToken(ctx, proj.ID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "sv"})
	require.NoError(t, err)
	w.tokens = map[string]string{"machine": mtok.PlainToken, "human": sess.SessionToken}
	return w
}

func (w *svWorld) newSecret(t *testing.T, maxReads *int) (*models.SecretNode, string) {
	t.Helper()
	n := w.seq.Add(1)
	val := fmt.Sprintf("sv-value-%d-v1", n)
	sec, err := w.a.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: fmt.Sprintf("svsecret%d", n), Value: []byte(val), ProjectID: w.projID, EnvironmentID: w.envID,
		Type: "password", CreatedBy: "svadmin", OwnerID: w.adminID, MaxReads: maxReads,
	})
	require.NoError(t, err)
	return sec, val
}

// svOutcome is what one read disclosed: the status and the value, or the error.
type svOutcome struct {
	Status int    // HTTP status, or gRPC code for gRPC paths
	Value  string // "" unless the read succeeded
	Err    string // error body/message, "" on success
}

func (o svOutcome) String() string {
	if o.Err == "" {
		return fmt.Sprintf("%d %q", o.Status, o.Value)
	}
	return fmt.Sprintf("%d err=%s", o.Status, o.Err)
}

var svPaths = []string{"rest-include-value", "rest-ref", "grpc"}

// read performs one value read on replica r through path as principal.
func (w *svWorld) read(t *testing.T, r *svReplica, path, principal string, sec *models.SecretNode) svOutcome {
	t.Helper()
	token := w.tokens[principal]
	switch path {
	case "rest-include-value", "rest-ref":
		url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec.ID)
		if path == "rest-ref" {
			url = "/api/v1/secrets/value?ref=svproj/prod/" + sec.Name
		}
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.router.ServeHTTP(rec, req)
		if rec.Code >= 200 && rec.Code < 300 {
			var resp struct {
				Data struct {
					Value string `json:"value"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			return svOutcome{Status: rec.Code, Value: resp.Data.Value}
		}
		return svOutcome{Status: rec.Code, Err: svNormalizeBody(rec.Body.String())}
	case "grpc":
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
		resp, err := r.grpc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(sec.ID), IncludeValue: true}) // #nosec G115 -- test IDs are small
		if err != nil {
			st, _ := status.FromError(err)
			return svOutcome{Status: int(st.Code()), Err: st.Message()}
		}
		return svOutcome{Status: 0, Value: resp.GetValue()}
	}
	t.Fatalf("unknown path %q", path)
	return svOutcome{}
}

// svNormalizeBody drops volatile fields (request ids, timestamps) from an error body.
func svNormalizeBody(body string) string {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return strings.TrimSpace(body)
	}
	for _, k := range []string{"request_id", "timestamp", "trace_id"} {
		delete(m, k)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%v;", k, m[k])
	}
	return b.String()
}

// svAvoidHourBoundary waits out the last seconds of a UTC hour, so a case that
// computes a window from "now" cannot straddle an hour (or day) change. Every
// timezone used here is a whole-hour offset from UTC.
func svAvoidHourBoundary(t *testing.T) {
	t.Helper()
	now := time.Now()
	next := now.Truncate(time.Hour).Add(time.Hour)
	if left := next.Sub(now); left < 20*time.Second {
		t.Logf("waiting %s for the hour boundary to pass", left+time.Second)
		time.Sleep(left + time.Second)
	}
}

func isoWeekday(tm time.Time) int {
	d := int(tm.Weekday())
	if d == 0 {
		return 7
	}
	return d
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	require.NoError(t, err)
	return loc
}

// svDenyHours is a valid [start, end) window that excludes local hour h.
func svDenyHours(h int) (int, int) {
	if h >= 1 {
		return 0, h // ends exactly at the current hour: EndHour is exclusive
	}
	return 1, 24
}

func (w *svWorld) putSchedule(t *testing.T, db *gorm.DB, secretID uint, days string, start, end int, tz string) {
	t.Helper()
	// Raw upsert on purpose: the closed (start == end) and unknown-timezone
	// cases are rejected by SetSecretSchedule's validation, and the read path
	// must still judge whatever row is there.
	var existing models.SecretAccessSchedule
	if err := db.Where("secret_node_id = ?", secretID).First(&existing).Error; err == nil {
		existing.AllowedDays, existing.StartHour, existing.EndHour, existing.Timezone = days, start, end, tz
		require.NoError(t, db.Save(&existing).Error)
		return
	}
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: secretID, AllowedDays: days, StartHour: start, EndHour: end, Timezone: tz,
	}).Error)
}

func (w *svWorld) rotate(t *testing.T, c *core.KeyorixCore, sec *models.SecretNode, val string) {
	t.Helper()
	_, err := c.RotateSecret(context.Background(), sec.ID, []byte(val), w.adminID, "svadmin")
	require.NoError(t, err)
}

func deleteLatestVersionRow(t *testing.T, db *gorm.DB, secretID uint) {
	t.Helper()
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secretID).Order("version_number DESC").First(&v).Error)
	require.NoError(t, db.Delete(&models.SecretVersion{}, v.ID).Error)
}

// svCase is one equivalence case: setup puts the secret in the state under
// test (it may read and change it several times); want lists the outcome per
// "<path>/<principal>" for the final read round.
type svCase struct {
	name     string
	maxReads *int
	setup    func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) (wantValue string)
	// deny: expected outcome class for every path/principal of the final round:
	// "" = allowed (value wantValue), otherwise the expected outcomes are taken
	// from svExpectedDenials[deny].
	deny string
}

// svExpectedDenials is the observed behaviour of the code BEFORE PERF-FIX-4,
// per path/principal (status + normalized error), recorded by running this
// test with the change reverted. The test passes unchanged on both. ERRMAP-1
// then deliberately changed the outside-schedule and max-reads rows from
// 500/Internal to 403/PermissionDenied and 409/FailedPrecondition with a
// stable code (secret_value_read_refusal_family_test.go).
var svExpectedDenials = map[string]map[string]svOutcome{
	"outside-schedule": {
		"rest-include-value/machine": {Status: 403, Err: "code=403;error=SecretAccessOutsideSchedule;message=secret access is not permitted outside the configured time window;success=false;"},
		"rest-include-value/human":   {Status: 403, Err: "code=403;error=SecretAccessOutsideSchedule;message=secret access is not permitted outside the configured time window;success=false;"},
		"rest-ref/machine":           {Status: 403, Err: "code=403;error=SecretAccessOutsideSchedule;message=secret access is not permitted outside the configured time window;success=false;"},
		"rest-ref/human":             {Status: 403, Err: "code=403;error=SecretAccessOutsideSchedule;message=secret access is not permitted outside the configured time window;success=false;"},
		"grpc/machine":               {Status: 7, Err: "secret access is not permitted outside the configured time window"},
		"grpc/human":                 {Status: 7, Err: "secret access is not permitted outside the configured time window"},
	},
	"deleted-secret": {
		"rest-include-value/machine": {Status: 403, Err: "code=403;error=Forbidden;message=Insufficient permissions;"},
		"rest-include-value/human":   {Status: 404, Err: "code=404;error=NotFound;message=Resource not found;"},
		"rest-ref/machine":           {Status: 403, Err: "code=403;error=Forbidden;message=Insufficient permissions;"},
		"rest-ref/human":             {Status: 404, Err: "code=404;error=NotFound;message=Resource not found;"},
		"grpc/machine":               {Status: 7, Err: "insufficient permissions"},
		"grpc/human":                 {Status: 5, Err: "secret not found"},
	},
	"no-versions": {
		"rest-include-value/machine": {Status: 500, Err: "code=500;error=InternalError;message=Failed to get secret value;success=false;"},
		"rest-include-value/human":   {Status: 500, Err: "code=500;error=InternalError;message=Failed to get secret value;success=false;"},
		"rest-ref/machine":           {Status: 500, Err: "code=500;error=InternalError;message=Failed to get secret value;success=false;"},
		"rest-ref/human":             {Status: 500, Err: "code=500;error=InternalError;message=Failed to get secret value;success=false;"},
		"grpc/machine":               {Status: 5, Err: "secret not found"},
		"grpc/human":                 {Status: 5, Err: "secret not found"},
	},
	"max-reads": {
		"rest-include-value/machine": {Status: 409, Err: "code=409;error=SecretMaxReadsExhausted;message=secret has reached its maximum number of reads;success=false;"},
		"rest-include-value/human":   {Status: 409, Err: "code=409;error=SecretMaxReadsExhausted;message=secret has reached its maximum number of reads;success=false;"},
		"rest-ref/machine":           {Status: 409, Err: "code=409;error=SecretMaxReadsExhausted;message=secret has reached its maximum number of reads;success=false;"},
		"rest-ref/human":             {Status: 409, Err: "code=409;error=SecretMaxReadsExhausted;message=secret has reached its maximum number of reads;success=false;"},
		"grpc/machine":               {Status: 9, Err: "secret has reached its maximum number of reads"},
		"grpc/human":                 {Status: 9, Err: "secret has reached its maximum number of reads"},
	},
}

func svCases() []svCase {
	one := 1
	return []svCase{
		{name: "no schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string { return v1 }},
		{name: "inside window (all days, 0-24 UTC)", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 24, "UTC")
			return v1
		}},
		{name: "outside window (closed every hour)", deny: "outside-schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 0, "UTC")
			return ""
		}},
		{name: "tz edge UTC+14: current local hour only", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			h := time.Now().In(mustLoc(t, "Pacific/Kiritimati")).Hour()
			w.putSchedule(t, w.a.db, sec.ID, "*", h, h+1, "Pacific/Kiritimati")
			return v1
		}},
		{name: "tz edge UTC+14: window ends at the current local hour", deny: "outside-schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			s, e := svDenyHours(time.Now().In(mustLoc(t, "Pacific/Kiritimati")).Hour())
			w.putSchedule(t, w.a.db, sec.ID, "*", s, e, "Pacific/Kiritimati")
			return ""
		}},
		{name: "tz edge UTC-12: current local hour only", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			h := time.Now().In(mustLoc(t, "Etc/GMT+12")).Hour()
			w.putSchedule(t, w.a.db, sec.ID, "*", h, h+1, "Etc/GMT+12")
			return v1
		}},
		{name: "tz edge UTC-12: window ends at the current local hour", deny: "outside-schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			s, e := svDenyHours(time.Now().In(mustLoc(t, "Etc/GMT+12")).Hour())
			w.putSchedule(t, w.a.db, sec.ID, "*", s, e, "Etc/GMT+12")
			return ""
		}},
		{name: "tz edge: today's weekday in the schedule's zone (UTC+14)", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			d := isoWeekday(time.Now().In(mustLoc(t, "Pacific/Kiritimati")))
			w.putSchedule(t, w.a.db, sec.ID, strconv.Itoa(d), 0, 24, "Pacific/Kiritimati")
			return v1
		}},
		{name: "tz edge: weekday of another zone (UTC-12) in a UTC+14 schedule", deny: "outside-schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			// UTC+14 and UTC-12 are 26 h apart, so their weekdays always differ.
			d := isoWeekday(time.Now().In(mustLoc(t, "Etc/GMT+12")))
			w.putSchedule(t, w.a.db, sec.ID, strconv.Itoa(d), 0, 24, "Pacific/Kiritimati")
			return ""
		}},
		{name: "unknown timezone fails open", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 0, "Mars/Olympus_Mons")
			return v1
		}},
		{name: "deleted secret", deny: "deleted-secret", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			require.NoError(t, w.a.c.DeleteSecret(context.Background(), sec.ID))
			return ""
		}},
		{name: "no versions", deny: "no-versions", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			require.NoError(t, w.a.db.Where("secret_node_id = ?", sec.ID).Delete(&models.SecretVersion{}).Error)
			return ""
		}},
		{name: "outside window AND no versions: the schedule denial fires first", deny: "outside-schedule", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 0, "UTC")
			require.NoError(t, w.a.db.Where("secret_node_id = ?", sec.ID).Delete(&models.SecretVersion{}).Error)
			return ""
		}},
		{name: "multiple versions", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.rotate(t, w.a.c, sec, v1+"-v2")
			w.rotate(t, w.a.c, sec, v1+"-v3")
			return v1 + "-v3"
		}},
		{name: "latest version deleted after a warm read", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.rotate(t, w.a.c, sec, v1+"-v2")
			require.Equal(t, v1+"-v2", w.read(t, w.a, "rest-include-value", "machine", sec).Value, "warm read")
			deleteLatestVersionRow(t, w.a.db, sec.ID)
			return v1
		}},
		{name: "schedule closed after a warm read, then reopened", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 24, "UTC")
			require.Equal(t, v1, w.read(t, w.a, "rest-include-value", "machine", sec).Value, "warm read")
			w.putSchedule(t, w.a.db, sec.ID, "*", 0, 0, "UTC")
			o := w.read(t, w.a, "rest-include-value", "machine", sec)
			require.Equal(t, svExpectedDenials["outside-schedule"]["rest-include-value/machine"], o, "closed after a warm read")
			require.NoError(t, w.a.db.Where("secret_node_id = ?", sec.ID).Delete(&models.SecretAccessSchedule{}).Error)
			return v1
		}},
		{name: "max reads 1", maxReads: &one, deny: "max-reads", setup: func(t *testing.T, w *svWorld, sec *models.SecretNode, v1 string) string {
			require.Equal(t, v1, w.read(t, w.a, "rest-include-value", "machine", sec).Value, "the one permitted read")
			return ""
		}},
	}
}

func TestValueReadScheduleVersion_Equivalence(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newSVWorld(t, backend, 1)
			for _, tc := range svCases() {
				t.Run(tc.name, func(t *testing.T) {
					svAvoidHourBoundary(t)
					sec, v1 := w.newSecret(t, tc.maxReads)
					want := tc.setup(t, w, sec, v1)
					for _, p := range svPaths {
						for _, principal := range []string{"machine", "human"} {
							key := p + "/" + principal
							got := w.read(t, w.a, p, principal, sec)
							if tc.deny == "" {
								wantStatus := 200
								if p == "grpc" {
									wantStatus = 0
								}
								assert.Equalf(t, svOutcome{Status: wantStatus, Value: want}, got, "%s", key)
								continue
							}
							exp, ok := svExpectedDenials[tc.deny][key]
							if !ok {
								t.Errorf("RECORD %s %s: %s", tc.deny, key, got)
								continue
							}
							assert.Equalf(t, exp, got, "%s", key)
						}
					}
				})
			}
		})
	}
}

// TestValueReadScheduleVersion_CrossReplica: two server processes (two pools,
// two read-path caches) on one Postgres schema. Replica A's caches are warm;
// every schedule change and every version write goes through replica B, and A's
// very next read must see it — for every path and principal.
func TestValueReadScheduleVersion_CrossReplica(t *testing.T) {
	w := newSVWorld(t, "postgres", 2)
	svAvoidHourBoundary(t)
	sec, v1 := w.newSecret(t, nil)
	ctx := context.Background()

	allowed := func(t *testing.T, step, want string) {
		t.Helper()
		for _, p := range svPaths {
			for _, principal := range []string{"machine", "human"} {
				wantStatus := 200
				if p == "grpc" {
					wantStatus = 0
				}
				assert.Equalf(t, svOutcome{Status: wantStatus, Value: want}, w.read(t, w.a, p, principal, sec), "%s: %s/%s", step, p, principal)
			}
		}
	}
	denied := func(t *testing.T, step string) {
		t.Helper()
		for _, p := range svPaths {
			for _, principal := range []string{"machine", "human"} {
				key := p + "/" + principal
				assert.Equalf(t, svExpectedDenials["outside-schedule"][key], w.read(t, w.a, p, principal, sec), "%s: %s", step, key)
			}
		}
	}

	allowed(t, "warm, no schedule", v1)
	allowed(t, "warm again", v1)

	// Schedule written on B (valid through core: today's weekday excluded).
	tomorrow := isoWeekday(time.Now().UTC().Add(24 * time.Hour))
	_, err := w.b.c.SetSecretSchedule(ctx, sec.ID, strconv.Itoa(tomorrow), 0, 24, "UTC")
	require.NoError(t, err)
	denied(t, "B set a schedule that excludes today")

	_, err = w.b.c.SetSecretSchedule(ctx, sec.ID, "*", 0, 24, "UTC")
	require.NoError(t, err)
	allowed(t, "B opened the schedule (update in place)", v1)

	h := time.Now().In(mustLoc(t, "Pacific/Kiritimati")).Hour()
	s, e := svDenyHours(h)
	_, err = w.b.c.SetSecretSchedule(ctx, sec.ID, "*", s, e, "Pacific/Kiritimati")
	require.NoError(t, err)
	denied(t, "B moved the window to end at the current UTC+14 hour")

	require.NoError(t, w.b.c.DeleteSecretSchedule(ctx, sec.ID))
	allowed(t, "B deleted the schedule", v1)

	w.rotate(t, w.b.c, sec, v1+"-v2")
	allowed(t, "B wrote version 2", v1+"-v2")

	w.rotate(t, w.b.c, sec, v1+"-v3")
	allowed(t, "B wrote version 3", v1+"-v3")

	deleteLatestVersionRow(t, w.b.db, sec.ID)
	allowed(t, "B deleted version 3", v1+"-v2")

	require.NoError(t, w.b.db.Where("secret_node_id = ?", sec.ID).Delete(&models.SecretVersion{}).Error)
	for _, p := range svPaths {
		for _, principal := range []string{"machine", "human"} {
			key := p + "/" + principal
			assert.Equalf(t, svExpectedDenials["no-versions"][key], w.read(t, w.a, p, principal, sec), "B deleted every version: %s", key)
		}
	}
}

// TestValueReadScheduleVersion_ConcurrentVersionWrites: machine value reads run
// while new versions are written. Every read succeeds with a value that was
// written at some point, and once the writers are done the read returns the
// latest version's value (checked against the by-version read, a path this
// change does not touch).
func TestValueReadScheduleVersion_ConcurrentVersionWrites(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newSVWorld(t, backend, 1)
			sec, v1 := w.newSecret(t, nil)
			ctx := context.Background()
			const rotations = 12
			written := map[string]bool{v1: true}
			for i := 2; i <= rotations+1; i++ {
				written[fmt.Sprintf("%s-c%d", v1, i)] = true
			}

			var wg sync.WaitGroup
			stop := make(chan struct{})
			var readsDone atomic.Int64
			for r := 0; r < 4; r++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						o := w.read(t, w.a, "rest-include-value", "machine", sec)
						if !assert.Equal(t, 200, o.Status, "concurrent read: %s", o) {
							return
						}
						assert.Truef(t, written[o.Value], "concurrent read returned a value never written: %q", o.Value)
						readsDone.Add(1)
					}
				}()
			}
			// One writer: concurrent rotations of one secret are serialized by
			// RotateSecret itself; what matters here is reads racing writes.
			for i := 2; i <= rotations+1; i++ {
				_, err := w.a.c.RotateSecret(ctx, sec.ID, []byte(fmt.Sprintf("%s-c%d", v1, i)), w.adminID, "svadmin")
				require.NoError(t, err)
			}
			close(stop)
			wg.Wait()
			require.Positive(t, readsDone.Load())

			var maxVer int
			require.NoError(t, w.a.db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", sec.ID).
				Select("COALESCE(MAX(version_number), 0)").Scan(&maxVer).Error)
			latest, err := w.a.c.GetSecretValueByVersion(ctx, sec.ID, maxVer)
			require.NoError(t, err)
			for _, p := range svPaths {
				for _, principal := range []string{"machine", "human"} {
					wantStatus := 200
					if p == "grpc" {
						wantStatus = 0
					}
					assert.Equalf(t, svOutcome{Status: wantStatus, Value: string(latest)}, w.read(t, w.a, p, principal, sec), "after the writers: %s/%s", p, principal)
				}
			}
			assert.Equal(t, fmt.Sprintf("%s-c%d", v1, rotations+1), string(latest))
		})
	}
}

// svScheduleVersionStmts returns the statements of stmts that read
// secret_access_schedules or secret_versions.
func svScheduleVersionStmts(stmts []string) []string {
	var out []string
	for _, s := range stmts {
		l := strings.ToLower(s)
		if strings.HasPrefix(strings.TrimSpace(l), "select") &&
			(strings.Contains(l, "secret_access_schedules") || strings.Contains(l, "secret_versions")) {
			out = append(out, s)
		}
	}
	return out
}

// TestValueReadScheduleVersion_OneStatement is the red/green: a warm machine
// value read (the bench path) reads the schedule and the latest-version
// generation in ONE statement. Before PERF-FIX-4 it was two
// (GetSecretAccessSchedule, then liveVersionsGeneration). Checked with and
// without a schedule (no schedule = the full-row miss path, a schedule = the
// warm schedule entry) on both backends.
func TestValueReadScheduleVersion_OneStatement(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			w := newSVWorld(t, backend, 1)
			for _, withSchedule := range []bool{false, true} {
				t.Run(fmt.Sprintf("schedule=%v", withSchedule), func(t *testing.T) {
					sec, v1 := w.newSecret(t, nil)
					if withSchedule {
						w.putSchedule(t, w.a.db, sec.ID, "*", 0, 24, "UTC")
					}
					for _, p := range []string{"rest-include-value", "rest-ref"} {
						// Warm every cache, then count the next read.
						require.Equal(t, v1, w.read(t, w.a, p, "machine", sec).Value)
						require.Equal(t, v1, w.read(t, w.a, p, "machine", sec).Value)
						w.a.mu.Lock()
						w.a.counting, w.a.stmts = true, nil
						w.a.mu.Unlock()
						o := w.read(t, w.a, p, "machine", sec)
						w.a.mu.Lock()
						w.a.counting = false
						all := append([]string(nil), w.a.stmts...)
						w.a.mu.Unlock()
						require.Equal(t, v1, o.Value)
						sv := svScheduleVersionStmts(all)
						t.Logf("%s %s schedule=%v: %d GORM statements in the read, %d on schedule/versions: %q", backend, p, withSchedule, len(all), len(sv), sv)
						assert.Lenf(t, sv, 1, "%s: a warm machine value read must read the schedule and the latest-version generation in one statement", p)
					}
				})
			}
		})
	}
}
