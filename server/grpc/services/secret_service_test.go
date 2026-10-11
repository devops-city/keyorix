package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// secretTestRig is a real core service over an in-memory DB with a seeded
// project/environment, plus the gRPC SecretService under test.
type secretTestRig struct {
	svc *SecretGRPCService
	db  *gorm.DB
}

func newSecretTestRig(t *testing.T) *secretTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Serialize access to the in-memory DB: the audit logging the service fires runs
	// in a detached goroutine (as on HTTP), so a single connection avoids SQLite
	// "database is locked" races between it and the test's own queries.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.DynamicSecretConfig{}, &models.SecretACL{}, &models.SecretAccessSchedule{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	// The owner user (id 1) — ListSecretsWithSharingInfo resolves owner usernames.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)

	// CreateSecret authorizes secrets.write at the target scope via the RBAC graph
	// (mirroring the HTTP handler), so the test DB needs real grants — the flat
	// UserContext.Permissions no longer gate creation. Seed a "writer" role that
	// grants secrets.read/write/delete and assign user 1 globally so the owner can
	// create/read/update/delete in every test below.
	require.NoError(t, db.Create(&models.Role{ID: writerRoleID, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 3, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 3}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID}).Error) // global (project 0, env 0)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return &secretTestRig{svc: NewSecretService(coreService), db: db}
}

// writerRoleID is the seeded role granting secrets.read/write/delete in the rig.
const writerRoleID = 1

// authCtx returns a context carrying a user with the given permissions, as the
// auth interceptor would populate after validating a session.
func authCtx(userID uint, username string, perms ...string) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: userID, Username: username, Permissions: perms})
}

func (r *secretTestRig) createSecret(t *testing.T, ctx context.Context, name, value string) *pb.Secret {
	t.Helper()
	sec, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: name, Value: value, ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)
	return sec
}

func TestSecretService_CreateSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	sec := r.createSecret(t, ctx, "db-password", "s3cr3t")
	assert.NotZero(t, sec.GetId())
	assert.Equal(t, "db-password", sec.GetName())
	assert.Equal(t, uint32(1), sec.GetProjectId())
	assert.Equal(t, uint32(1), sec.GetEnvironmentId())
	assert.Equal(t, uint32(1), sec.GetOwnerId())
	assert.Equal(t, "active", sec.GetStatus())
}

func TestSecretService_CreateSecret_Unauthenticated(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.CreateSecret(context.Background(), &pb.CreateSecretRequest{
		Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSecretService_CreateSecret_PermissionDenied(t *testing.T) {
	r := newSecretTestRig(t)
	// User 2 holds no RBAC role, so Authorize denies regardless of any flat
	// permission claimed in the context.
	ctx := authCtx(2, "reader", "secrets.read") // no write grant
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// sessionCtx returns a context for an interactive session-authenticated user (as
// the auth interceptor populates after validating a session token), with the
// second-factor flag set explicitly. SessionAuth gates the per-project MFA policy.
func sessionCtx(userID uint, username string, mfaEnabled bool, perms ...string) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{
			UserID: userID, Username: username, Permissions: perms,
			SessionAuth: true, MFAEnabled: mfaEnabled,
		})
}

// Per-project MFA policy (ADR-037) over gRPC: a project that requires MFA must
// deny an interactive session WITHOUT a second factor, mirroring the HTTP
// ProjectMFABlocked gate so the policy is not bypassable by switching transport.
// A session WITH MFA is allowed; a PAT (non-interactive, SessionAuth=false) is
// exempt; and a project that does not require MFA gates nobody.
func TestSecretService_PerProjectMFAGateOverGRPC(t *testing.T) {
	r := newSecretTestRig(t)
	// Project 1 (seeded) now mandates a second factor; project 2 does not.
	require.NoError(t, r.db.Model(&models.Project{}).Where("id = ?", 1).Update("require_mfa", true).Error)
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "open"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)

	create := func(ctx context.Context, name string, projectID, envID uint32) error {
		_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
			Name: name, Value: "v", ProjectId: projectID, EnvironmentId: envID, Type: "password",
		})
		return err
	}

	// Interactive session without MFA → denied on the MFA-required project, for both a
	// mutation and a read (ListSecrets shares the gate).
	noMFA := sessionCtx(1, "owner", false, "secrets.write", "secrets.read")
	err := create(noMFA, "k1", 1, 1)
	require.Error(t, err, "session without MFA must be denied on an MFA-required project")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = r.svc.ListSecrets(noMFA, &pb.ListSecretsRequest{ProjectId: ptrU32(1), EnvironmentId: ptrU32(1)})
	require.Error(t, err, "ListSecrets is gated by the per-project MFA policy too")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Same session, but the project does not require MFA → allowed.
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID, ProjectID: 2}).Error)
	require.NoError(t, create(noMFA, "k2", 2, 2), "a project without an MFA requirement gates nobody")

	// A session WITH a second factor is allowed on the MFA-required project.
	withMFA := sessionCtx(1, "owner", true, "secrets.write", "secrets.read")
	require.NoError(t, create(withMFA, "k3", 1, 1), "session with MFA is allowed")

	// A PAT is non-interactive (SessionAuth=false) and exempt — automation must not
	// break on an MFA-required project. authCtx leaves SessionAuth false.
	pat := authCtx(1, "owner", "secrets.write", "secrets.read")
	require.NoError(t, create(pat, "k4", 1, 1), "a PAT is exempt from the per-project MFA gate")
}

// Regression (gRPC scoped-authz hardening): CreateSecret must authorize
// secrets.write at the TARGET project/environment, not against the flat global
// permission set. A user whose secrets.write is granted only in project 1 must
// not be able to create a secret in project 2 — even though their flat
// UserContext.Permissions advertise secrets.write. Previously the gRPC handler
// checked only the flat list and let a project-scoped writer create anywhere.
func TestSecretService_CreateSecret_ScopedToOtherProjectDenied(t *testing.T) {
	r := newSecretTestRig(t)
	// A second project/environment the scoped writer has no grant in.
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)
	// User 3: writer role scoped to project 1 only (env 0 = all envs in project 1).
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)

	// The flat list advertises write — the bug would have honoured it everywhere.
	ctx := authCtx(3, "scoped", "secrets.write", "secrets.read")

	// In-scope (project 1): allowed.
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "in-scope", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)

	// Out-of-scope (project 2): denied.
	_, err = r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "cross-project", Value: "v", ProjectId: 2, EnvironmentId: 2, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Regression (gRPC scoped-authz hardening): per-secret reads/writes/deletes must
// authorize at the SECRET'S project/environment, not the flat global permission
// set. A user who even OWNS a secret in a project where they hold no RBAC grant
// must still be denied over gRPC — matching the HTTP scoped gate. Previously the
// flat secrets.* check passed and the downstream owner check let them through, so
// a project-1 writer could read/update/delete their secret sitting in project 2.
func TestSecretService_PerSecretOps_ScopedToOtherProjectDenied(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)
	// User 3: writer scoped to project 1 only — no grant in project 2.
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)
	// A secret in project 2 that user 3 OWNS (so the owner check alone would pass).
	require.NoError(t, r.db.Create(&models.SecretNode{
		ID: 50, Name: "p2-secret", ProjectID: 2, EnvironmentID: 2, OwnerID: 3, Status: "active", Type: "password",
	}).Error)

	// Flat list advertises every permission — the bug would have honoured it.
	ctx := authCtx(3, "scoped", "secrets.read", "secrets.write", "secrets.delete")

	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// user 3 holds secrets.* only scoped to project 1, not globally, so this
	// is not the narrow real-404 exception. A distinct code for "exists but
	// you can't touch it" vs. "doesn't exist" would be an existence oracle
	// across the project boundary; PermissionDenied here is what closes it —
	// see authorizeScopedTarget (conversions.go).
	_, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecret cross-project")

	_, err = r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecretValue cross-project")

	_, err = r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "UpdateSecret cross-project")

	_, err = r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "DeleteSecret cross-project")

	_, err = r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecretVersions cross-project")
}

// A scoped user CAN operate on a secret within a project where they hold the
// grant — confirming the scoped check didn't over-restrict legitimate access.
func TestSecretService_PerSecretOps_InScopeAllowed(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)
	ctx := authCtx(3, "scoped", "secrets.read", "secrets.write")

	created := r.createSecret(t, ctx, "in-scope", "v") // project 1, where user 3 has the grant
	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "in-scope", got.GetName())
}

func TestSecretService_CreateSecret_Validation(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write")
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestSecretService_CreateSecret_NameLengthMatchesHTTP verifies gRPC rejects an
// over-255-char secret Name with the same limit HTTP's `validate:"...,max=255"` tag
// enforces (backlog #190) — internal/core.CreateSecret, which both transports call,
// must reject it rather than only the (gRPC-bypassed) HTTP validator.
func TestSecretService_CreateSecret_NameLengthMatchesHTTP(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: strings.Repeat("a", 256), Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err, "a 256-char secret name must be rejected over gRPC, matching HTTP's 255-char cap")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// A name at exactly the limit is still accepted.
	_, err = r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: strings.Repeat("a", 255), Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)
}

func TestSecretService_GetSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "api-key", "abc123")

	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), got.GetId())
	assert.Equal(t, "api-key", got.GetName())
}

func TestSecretService_GetSecret_NotFound(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "reader", "secrets.read")
	_, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: 9999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretService_GetSecretValue(t *testing.T) {
	r := newSecretTestRig(t)
	// SESSION-PERF #2403 follow-up (item 3): GetSecretValue now checks its audit
	// write synchronously (audit-before-disclosure) — same fixture gap/fix as
	// TestSecretService_GetSecretValue_RecordsAccessLogAndAudit below.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "token", "the-value")

	val, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "the-value", val.GetValue())
	assert.Equal(t, "token", val.GetName())
}

// A secret read over gRPC must land in the audit trail and the secret-access log,
// exactly as the HTTP reveal handler records it. Without it, the anomaly detector
// (which feeds on secret_access_logs) is blind to reads that arrive over gRPC, so
// secrets could be exfiltrated over gRPC invisibly. The write is detached/async,
// so poll for it.
func TestSecretService_GetSecretValue_RecordsAccessLogAndAudit(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "token", "the-value")

	_, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		var audits, logs int64
		r.db.Model(&models.AuditEvent{}).
			Where("event_type = ? AND secret_node_id = ?", "secret.read", created.GetId()).Count(&audits)
		r.db.Model(&models.SecretAccessLog{}).
			Where("secret_node_id = ? AND action = ?", created.GetId(), "read").Count(&logs)
		return audits == 1 && logs == 1
	}, 2*time.Second, 10*time.Millisecond,
		"a gRPC secret read must write one secret.read audit event and one access-log row")

	// The access-log row attributes the read to the caller, for forensics / anomaly.
	var alog models.SecretAccessLog
	require.NoError(t, r.db.Where("secret_node_id = ?", created.GetId()).First(&alog).Error)
	assert.Equal(t, "owner", alog.AccessedBy)
	assert.Equal(t, uint(created.GetId()), alog.SecretNodeID)
}

// Secret create/update/delete over gRPC must be audited exactly as on HTTP — the
// core methods do not audit internally, the handler does. Without this, the entire
// secret lifecycle was invisible in the audit trail when driven over gRPC.
func TestSecretService_WriteOps_AuditedOverGRPC(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read", "secrets.delete")

	created := r.createSecret(t, ctx, "lifecycle", "v1")

	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: created.GetId(), Value: strPtr("v2")})
	require.NoError(t, err)

	_, err = r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: created.GetId()})
	require.NoError(t, err)

	// Each op writes its audit event asynchronously; poll until all three landed.
	countEvent := func(evType string) int64 {
		var n int64
		r.db.Model(&models.AuditEvent{}).
			Where("event_type = ? AND secret_node_id = ?", evType, created.GetId()).Count(&n)
		return n
	}
	require.Eventually(t, func() bool {
		return countEvent("secret.created") == 1 &&
			countEvent("secret.updated") == 1 &&
			countEvent("secret.deleted") == 1
	}, 2*time.Second, 10*time.Millisecond,
		"create/update/delete over gRPC must each write one audit event")

	// The update event carries a before/after diff (it records what changed).
	var upd models.AuditEvent
	require.NoError(t, r.db.Where("event_type = ? AND secret_node_id = ?", "secret.updated", created.GetId()).First(&upd).Error)
	assert.NotEmpty(t, upd.Diff, "an update over gRPC must record a diff, like HTTP")
}

func TestSecretService_UpdateSecret(t *testing.T) {
	r := newSecretTestRig(t)
	// SESSION-PERF #2403 follow-up (item 3): this test's own GetSecretValue call
	// below now checks its audit write synchronously (audit-before-disclosure) —
	// same fixture gap/fix as TestSecretService_GetSecretValue above.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "rotate-me", "old")

	updated, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: created.GetId(), Value: strPtr("new-value"),
	})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), updated.GetId())

	val, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "new-value", val.GetValue())
}

func TestSecretService_DeleteSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read", "secrets.delete")
	created := r.createSecret(t, ctx, "temp", "v")

	_, err := r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: created.GetId()})
	require.NoError(t, err)

	_, err = r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretService_ListSecrets(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	r.createSecret(t, ctx, "one", "a")
	r.createSecret(t, ctx, "two", "b")

	resp, err := r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetSecrets()), 2)
	assert.GreaterOrEqual(t, resp.GetTotal(), uint32(2))
}

func TestSecretService_GetSecretVersions(t *testing.T) {
	r := newSecretTestRig(t)
	// SESSION-PERF #2403 follow-up (item 3): GetSecretVersions' own best-effort
	// audit-as-a-read call now checks its write synchronously and fails closed —
	// same fixture gap/fix as TestSecretService_GetSecretValue above.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "versioned", "v1")

	resp, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetVersions()), 1)
}

func strPtr(s string) *string { return &s }

func TestSecretService_SetSecretAutoRotate(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "rotatable", "v")

	_, err := r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{
		Id: sec.GetId(), Enabled: true, Length: 48, Charset: "hex",
	})
	require.NoError(t, err)

	var s models.SecretNode
	require.NoError(t, r.db.First(&s, sec.GetId()).Error)
	assert.True(t, s.AutoRotate)
	assert.Equal(t, 48, s.RotationLength)
	assert.Equal(t, "hex", s.RotationCharset)
}

func TestSecretService_SetSecretAutoRotate_BadCharset(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "rotatable", "v")

	_, err := r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{
		Id: sec.GetId(), Enabled: true, Charset: "klingon",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretService_SetSecretAutoRotate_Unauthenticated(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.SetSecretAutoRotate(context.Background(), &pb.SetSecretAutoRotateRequest{Id: 1, Enabled: true})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSecretService_SetSecretAutoRotate_PermissionDenied(t *testing.T) {
	r := newSecretTestRig(t)
	owner := authCtx(1, "writer", "secrets.write", "secrets.read")
	sec := r.createSecret(t, owner, "rotatable", "v")

	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// user 2 holds no secrets.write grant anywhere, not even globally, so
	// this is not the narrow real-404 exception — see authorizeScopedTarget's
	// doc comment (conversions.go).
	ctx := authCtx(2, "reader", "secrets.read") // no write grant
	_, err := r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{Id: sec.GetId(), Enabled: true})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// #2971 (AUDIT-UX-3): gRPC parity with REST's total_reads. GetSecret and
// GetSecretVersions report the secret's lifetime value-read count
// (core.SecretTotalReads: access-log rows with action read), not the per-version
// max_reads counters (which stay 0 for a secret without max_reads).
func TestSecretService_TotalReads_GetSecretAndVersions(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "counted", "the-value")

	before, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	require.NotNil(t, before.TotalReads, "total_reads is reported on GetSecret (0 before any read)")
	assert.Equal(t, int64(0), before.GetTotalReads())

	for i := 0; i < 2; i++ {
		_, err = r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
		require.NoError(t, err)
	}

	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	require.NotNil(t, got.TotalReads)
	assert.Equal(t, int64(2), got.GetTotalReads(), "two value reads; the version max_reads counter stays 0 for this secret")

	vers, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: created.GetId()})
	require.NoError(t, err)
	require.NotNil(t, vers.TotalReads)
	want, err := r.svc.core.SecretTotalReads(ctx, uint(created.GetId()))
	require.NoError(t, err)
	assert.Equal(t, want, vers.GetTotalReads(), "versions listing reports the same figure as core.SecretTotalReads")
	assert.GreaterOrEqual(t, vers.GetTotalReads(), int64(2))

	// Lists do not carry it (REST: omitted from listings).
	list, err := r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{})
	require.NoError(t, err)
	for _, s := range list.GetSecrets() {
		assert.Nil(t, s.TotalReads, "ListSecrets must not carry total_reads")
	}
}

// AUDIT-UX-2 item 3: listing version history over gRPC is audited as
// secret.versions_listed with an access-log row of action "versions_list"
// (anomaly detection reads every action), never as secret.read: no value is
// returned. Mirrors the HTTP handler (server/http
// TestCLISecretDeleteFlow_WritesNoSecretRead).
func TestSecretService_GetSecretVersions_AuditsListingNotRead(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "token", "the-value")

	_, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: created.GetId()})
	require.NoError(t, err)

	count := func(q string, args ...any) int64 {
		var n int64
		r.db.Raw(q, args...).Scan(&n)
		return n
	}
	assert.Equal(t, int64(1), count("SELECT COUNT(*) FROM audit_events WHERE event_type = ? AND secret_node_id = ?", core.EventSecretVersionsListed, created.GetId()))
	assert.Zero(t, count("SELECT COUNT(*) FROM audit_events WHERE event_type = ? AND secret_node_id = ?", "secret.read", created.GetId()), "a version listing is not a value read")
	assert.Equal(t, int64(1), count("SELECT COUNT(*) FROM secret_access_logs WHERE secret_node_id = ? AND action = ?", created.GetId(), core.AccessActionVersionsList))
	assert.Zero(t, count("SELECT COUNT(*) FROM secret_access_logs WHERE secret_node_id = ? AND action = ?", created.GetId(), "read"))
}
