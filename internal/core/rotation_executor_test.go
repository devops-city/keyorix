package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func rotationExecCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.RotationPolicy{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.UserRole{},
		&models.GroupRole{}, &models.UserGroup{}, &models.Group{},
	))
	// ListSecrets(ProjectID) JOINs environments, so the scope needs a real env row.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	return c, db, fixed
}

func seedRotatableSecret(t *testing.T, db *gorm.DB, id uint, name string, autoRotate bool, lastRotated time.Time) {
	t.Helper()
	lr := lastRotated
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: name, ProjectID: 1, EnvironmentID: 1, IsSecret: true,
		Status: "active", AutoRotate: autoRotate, LastRotatedAt: &lr, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("original-" + name),
		EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

func latestVersion(t *testing.T, db *gorm.DB, secretID uint) *models.SecretVersion {
	t.Helper()
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secretID).Order("version_number desc").First(&v).Error)
	return &v
}

func TestRunAutoRotation_RotatesOverdueOptedInOnly(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)

	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))   // overdue + opted-in → rotate
	seedRotatableSecret(t, db, 2, "fresh-managed", true, fixed.Add(-5*24*time.Hour))  // opted-in but not due → skip
	seedRotatableSecret(t, db, 3, "due-external", false, fixed.Add(-60*24*time.Hour)) // overdue but not opted-in → skip

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the overdue, opted-in secret rotates")

	// s1: new version with a freshly generated (different) value; LastRotatedAt advanced.
	v1 := latestVersion(t, db, 1)
	assert.Equal(t, 2, v1.VersionNumber, "due-managed secret gained a new version")
	assert.NotEqual(t, "original-due-managed", string(v1.EncryptedValue))
	assert.Len(t, string(v1.EncryptedValue), rotatedValueLength)
	var s1 models.SecretNode
	require.NoError(t, db.First(&s1, 1).Error)
	require.NotNil(t, s1.LastRotatedAt)
	assert.True(t, s1.LastRotatedAt.After(fixed.Add(-time.Minute)), "LastRotatedAt advanced to now")

	// s2 and s3 are untouched (still on version 1).
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber, "not-due secret unchanged")
	assert.Equal(t, 1, latestVersion(t, db, 3).VersionNumber, "non-opted-in secret unchanged")
}

// TestRunAutoRotation_StampsRotationStateOnSuccess is #G43: SetRotationState was
// fully wired at the storage layer (with a doc comment claiming "called by the
// rotation executor when a rotation job starts, completes, or fails") but the
// executor never actually called it, so GetRotationState always reported "idle"
// regardless of real activity.
func TestRunAutoRotation_StampsRotationStateOnSuccess(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	info, err := c.GetRotationState(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, RotationStateSucceeded, info.State)
	assert.Empty(t, info.LastRotationError)
}

// TestRunAutoRotation_StampsRotationStateOnFailure covers the failure branch of
// the same #G43 gap: a backend rotation failure must also be visible via
// GetRotationState, not just in the run's return value / audit trail.
func TestRunAutoRotation_StampsRotationStateOnFailure(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)

	info, err := c.GetRotationState(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, RotationStateFailed, info.State)
	assert.Contains(t, info.LastRotationError, "connection refused")
}

// TestRunAutoRotation_AuditEventsCarryProjectID is #G23: every rotation-domain
// audit event used to be written with ProjectID=nil, even though the secret
// (and its ProjectID) is known at every one of these call sites — an operator
// filtering the audit trail by project couldn't find auto-rotation activity.
func TestRunAutoRotation_AuditEventsCarryProjectID(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Find(&events).Error)
	require.NotEmpty(t, events)
	for _, e := range events {
		require.NotNil(t, e.ProjectID, "rotation audit event %q must carry a ProjectID", e.EventType)
		assert.Equal(t, uint(1), *e.ProjectID)
	}
}

func TestRunAutoRotation_InactivePolicyIgnored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "off", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// GORM applies the column default (is_active=true) for a zero-value bool on Create,
	// so force it false explicitly to model an inactive policy.
	require.NoError(t, db.Model(&models.RotationPolicy{}).Where("id = ?", 1).Update("is_active", false).Error)
	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no rotation under an inactive policy")
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

func TestSetSecretAutoRotate_TogglesAndPersists(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))

	// Enable with a generator spec.
	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, AutoRotateSpec{Enabled: true, Length: 48, Charset: "hex"}, 9))
	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.True(t, s.AutoRotate)
	assert.Equal(t, 48, s.RotationLength)
	assert.Equal(t, "hex", s.RotationCharset)

	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, AutoRotateSpec{Enabled: false}, 9))
	require.NoError(t, db.First(&s, 1).Error)
	assert.False(t, s.AutoRotate)
}

func TestSetSecretAutoRotate_ValidatesSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Charset: "klingon"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation charset")

	err = c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Length: 5000}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestGenerateRotatedValueSpec_LengthAndCharset(t *testing.T) {
	// hex charset, custom length.
	v, err := generateRotatedValueSpec(48, "hex")
	require.NoError(t, err)
	assert.Len(t, v, 48)
	for _, ch := range v {
		assert.Contains(t, charsetHex, string(ch))
	}
	// length 0 → default; unknown charset → alphanumeric (fail-safe, never empty).
	v, err = generateRotatedValueSpec(0, "bogus")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueLength)
	for _, ch := range v {
		assert.Contains(t, charsetAlphanumeric, string(ch))
	}
	// below-min length clamps up, not to zero-length.
	v, err = generateRotatedValueSpec(2, "")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueMinLength)
}

// The executor honors a secret's generator spec.
func TestRunAutoRotation_UsesSecretSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// Overdue, opted-in, hex/16.
	lr := fixed.Add(-60 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "hex-key", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationLength: 16, RotationCharset: "hex", LastRotatedAt: &lr, CreatedAt: lr,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lr,
	}).Error)

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Len(t, string(v.EncryptedValue), 16)
	for _, ch := range string(v.EncryptedValue) {
		assert.Contains(t, charsetHex, string(ch))
	}
}

func TestGenerateRotatedValue_UniqueAndCharset(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		v, err := generateRotatedValue()
		require.NoError(t, err)
		assert.Len(t, v, rotatedValueLength)
		for _, ch := range v {
			assert.Contains(t, rotatedValueCharset, string(ch))
		}
		assert.False(t, seen[v], "values must not repeat")
		seen[v] = true
	}
}

// fakeExecutor records the (ref, value) it was asked to rotate and can fail on demand.
type fakeExecutor struct {
	name   string
	gotRef string
	gotVal string
	called bool
	err    error
}

func (f *fakeExecutor) Name() string { return f.name }
func (f *fakeExecutor) Type() string { return "fake" }
func (f *fakeExecutor) Rotate(_ context.Context, ref, val string) error {
	f.called = true
	f.gotRef, f.gotVal = ref, val
	return f.err
}

func seedBackendSecret(t *testing.T, db *gorm.DB, id uint, backend, ref string, lastRotated time.Time) {
	t.Helper()
	lr := lastRotated
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: "upstream-cred", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationBackend: backend, RotationRef: ref, LastRotatedAt: &lr, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

func backendPolicyCore(t *testing.T, fake *fakeExecutor) (*KeyorixCore, *gorm.DB, time.Time) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	return c, db, fixed
}

// Backend rotation: the executor applies the new value upstream, then it's stored.
func TestRunAutoRotation_BackendApplied(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	require.True(t, fake.called, "the upstream executor was invoked")
	assert.Equal(t, "app_svc", fake.gotRef)
	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber, "new value stored after upstream success")
	assert.Equal(t, fake.gotVal, string(v.EncryptedValue), "stored value matches what was applied upstream")
}

// If the upstream apply fails, the value is NOT stored (no drift between Keyorix and upstream).
func TestRunAutoRotation_BackendFailureNotStored(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "a failed upstream apply rotates nothing")
	assert.True(t, fake.called)
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber, "value not stored on upstream failure")
}

// An unknown backend name (no executor registered) is skipped, not stored.
func TestRunAutoRotation_UnknownBackendSkipped(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "nope", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.False(t, fake.called, "the registered executor is not invoked for a different backend name")
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

func TestSetSecretAutoRotate_BackendRefBothOrNeither(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)

	// backend without ref → error
	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be set together")

	// both set, backend exists, actor holds project_admin → ok
	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9))
	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Equal(t, "pg", s.RotationBackend)
	assert.Equal(t, "app_svc", s.RotationRef)
}

func TestSetSecretAutoRotate_RejectsUnknownBackend(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	// No manager configured → backend reference rejected.
	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rotation backends")

	// Manager present but the named backend is not registered → rejected.
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "other"}}))
	err = c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation backend")
}

// TestSetSecretAutoRotate_BindingBackendRequiresAdminAuthority pins #90: binding a
// rotation backend to a secret is gated only by scoped secrets.write on the secret,
// so any project editor could point an org-wide-credentialed backend (AWS/GCP/Azure
// IAM, a shared DB superuser) at a ref they can influence and have the next
// scheduler run mint that credential into their own readable secret. A non-admin
// actor must be refused.
func TestSetSecretAutoRotate_BindingBackendRequiresAdminAuthority(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
	ctx := context.Background()
	// actor 9 has secrets.write on the secret (enforced by the transport layer,
	// out of scope here) but NO role at all — the realistic "project editor" persona.

	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err, "a non-admin actor must not be able to bind a rotation backend")
	assert.Contains(t, err.Error(), "admin authority")

	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Empty(t, s.RotationBackend, "the secret must not end up bound to the backend")
}

// TestSetSecretAutoRotate_InKeyorixRotationNoAdminRequired is the positive control:
// the common case (no external backend — Keyorix regenerates the value itself) has
// no cross-scope credential-minting risk and is unaffected by the new ceiling.
func TestSetSecretAutoRotate_InKeyorixRotationNoAdminRequired(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true}, 9),
		"enabling in-Keyorix rotation (no backend) needs no elevated authority")
}

// TestSetSecretAutoRotate_UnbindingBackendRequiresAdminAuthority pins the unbind side of
// #90: an admin decided this secret should auto-rotate against an upstream backend, and
// clearing that binding is just as security-relevant as creating it. Before this fix, the
// admin-authority guard fired only when spec.Backend != "" — a plain secrets.write caller
// (no admin authority) could pass Backend: "" against an already-bound secret and silently
// strip an admin-configured rotation binding they were never allowed to set up in the
// first place.
func TestSetSecretAutoRotate_UnbindingBackendRequiresAdminAuthority(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-24*time.Hour))
	ctx := context.Background()
	// actor 9 has secrets.write on the secret (enforced by the transport layer, out of
	// scope here) but NO role at all — the realistic "project editor" persona.

	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true}, 9)
	require.Error(t, err, "a non-admin actor must not be able to unbind an existing rotation backend")
	assert.Contains(t, err.Error(), "admin authority")

	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Equal(t, "pg", s.RotationBackend, "the existing binding must survive a refused unbind attempt")
	assert.Equal(t, "app_svc", s.RotationRef)
}

// TestSetSecretAutoRotate_AdminCanUnbindBackend is the positive control: an actor who DOES
// hold admin authority can still clear an existing rotation-backend binding.
func TestSetSecretAutoRotate_AdminCanUnbindBackend(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-24*time.Hour))
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)

	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true}, 9),
		"an admin caller can clear an existing rotation-backend binding")

	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Empty(t, s.RotationBackend, "binding cleared")
	assert.Empty(t, s.RotationRef, "ref cleared")
}

// TestSetSecretAutoRotate_UnboundSecretNoAdminRequired confirms the guard stays scoped to
// an actual unbind: a secret with no backend ever bound, updated with Backend: "" again,
// is a no-op and needs no elevated authority (mirrors the in-Keyorix-rotation control
// above, but explicit about the "nothing to unbind" case).
func TestSetSecretAutoRotate_UnboundSecretNoAdminRequired(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: false}, 9),
		"clearing a backend that was never bound is a no-op and needs no elevated authority")
}

// TestSetSecretAutoRotate_RejectsDangerousRefChars pins the earliest, shared layer of
// defense against a malicious rotation_ref: SetSecretAutoRotate is the single
// core-layer choke point every transport (HTTP/gRPC/CLI) goes through to set a
// rotation ref, so rejecting dangerous metacharacters here — BEFORE the ref is ever
// persisted to secret.RotationRef — covers every backend without relying solely on
// each backend's own (partial, discovered-after-the-fact) defenses.
func TestSetSecretAutoRotate_RejectsDangerousRefChars(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{"slash", "svc/app"},
		{"question-mark", "svc?app"},
		{"hash", "svc#app"},
		{"percent", "svc%app"},
		{"single-quote", "svc'app"},
		{"double-quote", `svc"app`},
		{"backslash", `svc\app`},
		{"semicolon", "svc;app"},
		{"sql-injection-attempt", "app_svc'; DROP TABLE users; --"},
		{"path-traversal-attempt", "allowed-prefix/../victim"},
		{"control-null", "svc\x00app"},
		{"control-newline", "svc\napp"},
		{"control-tab", "svc\tapp"},
		{"control-del", "svc\x7fapp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, db, fixed := rotationExecCore(t)
			seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
			c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
			require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin", BypassesPermissionChecks: true}).Error)
			require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)

			err := c.SetSecretAutoRotate(context.Background(), 1,
				AutoRotateSpec{Enabled: true, Backend: "pg", Ref: tc.ref}, 9)
			require.Error(t, err, "ref %q must be rejected", tc.ref)
			assert.Contains(t, err.Error(), "disallowed")

			var s models.SecretNode
			require.NoError(t, db.First(&s, 1).Error)
			assert.Empty(t, s.RotationRef, "the dangerous ref must never be persisted")
		})
	}
}

// TestSetSecretAutoRotate_AllowsRealisticLegitimateRefs pins that the new denylist does
// NOT break real ref shapes already exercised by the per-backend tests (awsiam_test.go,
// gcpsa_test.go, postgres_test.go, mysql_test.go): a strict allowlist would have broken
// these, which is why validateRotationRef is a denylist instead.
func TestSetSecretAutoRotate_AllowsRealisticLegitimateRefs(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{"gcp-service-account-email", "svc-app@my-project.iam.gserviceaccount.com"},
		{"aws-iam-username-with-allowed-punctuation", "svc-app+ci=prod,tier1"},
		{"plain-postgres-mysql-role-name", "app_svc"},
		{"azure-app-object-id-guid", "3fa85f64-5717-4562-b3fc-2c963f66afa6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, db, fixed := rotationExecCore(t)
			seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
			c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
			require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin", BypassesPermissionChecks: true}).Error)
			require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)

			err := c.SetSecretAutoRotate(context.Background(), 1,
				AutoRotateSpec{Enabled: true, Backend: "pg", Ref: tc.ref}, 9)
			require.NoError(t, err, "legitimate ref %q must be accepted", tc.ref)

			var s models.SecretNode
			require.NoError(t, db.First(&s, 1).Error)
			assert.Equal(t, tc.ref, s.RotationRef)
		})
	}
}

// fakeGenExecutor is a generate-upstream backend: GenerateUpstream mints the value.
type fakeGenExecutor struct {
	name   string
	value  string
	gotRef string
	err    error
}

func (f *fakeGenExecutor) Name() string { return f.name }
func (f *fakeGenExecutor) Type() string { return "fakegen" }
func (f *fakeGenExecutor) Rotate(context.Context, string, string) error {
	return errors.New("use GenerateUpstream")
}
func (f *fakeGenExecutor) GenerateUpstream(_ context.Context, ref string) (string, error) {
	f.gotRef = ref
	return f.value, f.err
}

// For a generate-upstream backend the STORED value is what the upstream minted, not the
// Keyorix-generated candidate.
func TestRunAutoRotation_GenerateUpstreamStored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	fake := &fakeGenExecutor{name: "cloud", value: `{"access_key_id":"AKIANEW","secret_access_key":"s"}`}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, "svc-app", fake.gotRef)
	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Equal(t, fake.value, string(v.EncryptedValue), "stored value is the upstream-minted one, not a generated candidate")
}

// A generate-upstream failure stores nothing.
func TestRunAutoRotation_GenerateUpstreamFailureNotStored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	fake := &fakeGenExecutor{name: "cloud", err: errors.New("LimitExceeded")}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

// failingProjectSecretsStore wraps LocalStorage and fails ListSecrets only for
// filter.ProjectID == failProject, simulating a transient storage error scoped to
// exactly one rotation policy's scope while a sibling project's policy still succeeds.
func failingProjectSecretsStore(inner storage.Storage, failProject uint) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSecrets: func(next storage.Storage, ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
			if filter.ProjectID != nil && *filter.ProjectID == failProject {
				return nil, 0, errors.New("simulated storage failure")
			}
			return next.ListSecrets(ctx, filter)
		},
	})
}

// #364: before the fix, a scopedPolicySecrets failure for one policy silently skipped
// every auto-rotate-enabled, possibly critically-overdue secret in its scope with ZERO
// operator-visible trace — contrast the dependency-list error a few lines later in the
// same function, which already logged and degraded gracefully. This pins that (a) a
// healthy policy's overdue secret still rotates (the run doesn't abort), and (b) the
// failure is now logged, unlike before.
func TestRunAutoRotation_LogsAndContinuesOnScopedSecretsError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.RotationPolicy{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
	))
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "healthy-proj"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "broken-proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)
	pid1, pid2 := uint(1), uint(2)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "healthy-policy", Scope: "project", ProjectID: &pid1, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 2, Name: "broken-policy", Scope: "project", ProjectID: &pid2, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "due-healthy", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, LastRotatedAt: timePtr(fixed.Add(-60 * 24 * time.Hour)), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	// A due, auto-rotate-enabled secret under the BROKEN policy's scope — this must be
	// skipped (its ListSecrets call errors before this row is ever seen), never rotated.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "due-broken", ProjectID: 2, EnvironmentID: 2, IsSecret: true, Status: "active",
		AutoRotate: true, LastRotatedAt: timePtr(fixed.Add(-90 * 24 * time.Hour)), CreatedAt: fixed.Add(-90 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 2, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: fixed.Add(-90 * 24 * time.Hour),
	}).Error)

	c := &KeyorixCore{storage: failingProjectSecretsStore(store.NewLocalStorage(db), pid2)}
	c.now = func() time.Time { return fixed }

	var n int
	logged := captureLog(t, func() {
		n, err = c.RunAutoRotation(context.Background())
	})
	require.NoError(t, err, "a single policy's scope-listing failure must not abort the whole run")
	assert.Equal(t, 1, n, "the healthy policy's due secret still rotates")
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber, "the secret under the broken policy's scope was never even considered, so it's untouched")

	assert.Contains(t, logged, "broken-policy", "the failing policy's name must appear in the operator-visible log line")
	assert.Contains(t, logged, "simulated storage failure")
}

func timePtr(t time.Time) *time.Time { return &t }

// #194: a generate-upstream backend whose old-credential delete failed must NOT be
// reported as a clean, unconditional success. The new credential is minted upstream
// (often returned only once, e.g. a cloud key API), so RunAutoRotation MUST still
// store it — but the run has to surface the leftover credential as a distinct,
// operator-visible partial-failure signal rather than a normal "auto-rotated" line,
// so it's neither silently swallowed nor lost from the audit trail. This exercises
// the orchestration layer (rotateOneSecret's PartialRotationError branch); the
// per-backend executors (AWS IAM/Azure AD/GCP SA) that construct PartialRotationError
// are covered individually in internal/rotation/*_test.go.
func TestRunAutoRotation_GenerateUpstreamPartialDelete_StoresButFlagsIncomplete(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	newCred := `{"access_key_id":"AKIANEW","secret_access_key":"s3cr3t"}`
	fake := &fakeGenExecutor{name: "cloud", err: &rotation.PartialRotationError{
		Value: newCred,
		Err:   errors.New("aws-iam: rotated \"svc-app\" but failed to delete prior access key(s) [AKIAOLD] (the old credential is still live and must be removed manually): AccessDenied"),
	}}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	// The new credential IS stored (it must not be discarded/orphaned)...
	require.Equal(t, 1, n, "the new credential is still stored despite the incomplete cleanup")
	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Equal(t, newCred, string(v.EncryptedValue))

	// ...but the run must NOT report this as a clean, indistinguishable success: exactly
	// one auto-rotation audit event, and it must flag the leftover credential distinctly.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Find(&events).Error)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Description, "INCOMPLETE", "a surviving old credential must be a distinct signal, not a silent success")
	assert.Contains(t, events[0].Description, "AKIAOLD", "the audit trail must name the leftover credential for operator cleanup")
	assert.NotContains(t, events[0].Description, "auto-rotated secret", "must not read as the normal clean-success line")
}

// A rotation failure broadcasts a single summary notification (fakeSink is defined in
// notification_dispatch_test.go).
func TestRunAutoRotation_NotifiesFailures(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	sink := &fakeSink{}
	c.SetNotificationSink(sink)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour)) // name "upstream-cred"

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Len(t, sink.events, 1)
	assert.Equal(t, "rotation.failed", sink.events[0].Type)
	assert.Contains(t, sink.events[0].Title, "1 secret")
	// Group 1 fix: the broadcast reaching an external webhook/chat channel is
	// allowlist-built (secret name + a generic phrase only) — it must NOT carry
	// the upstream backend name, ref, or raw error text. That detail stays in
	// the audit trail (writeAuditEventFull) and rotation-state API, both
	// internal to Keyorix.
	assert.Contains(t, sink.events[0].Message, "upstream-cred")
	assert.NotContains(t, sink.events[0].Message, "connection refused", "the raw upstream error must not reach an external notification channel")
	assert.NotContains(t, sink.events[0].Message, "app_svc", "the upstream ref must not reach an external notification channel")
}

// TestRunAutoRotation_NotifiesFailures_LogsWhenNoChannelAccepts is a regression test
// for #221: when no configured notification channel could accept the rotation-
// failure broadcast (e.g. an email-only deployment with no broadcast destination —
// fakeSink.refuse stands in for that), the run must still succeed and the rotation-
// failure audit event (EventAutoRotationFailures) must still be written accurately —
// but the alert-delivery gap itself must be logged, not silently swallowed.
func TestRunAutoRotation_NotifiesFailures_LogsWhenNoChannelAccepts(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	sink := &fakeSink{refuse: true}
	c.SetNotificationSink(sink)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	var rotated int
	var err error
	logged := captureLog(t, func() {
		rotated, err = c.RunAutoRotation(context.Background())
	})
	require.NoError(t, err)
	assert.Equal(t, 0, rotated)
	assert.Empty(t, sink.events, "no channel accepted the alert")
	assert.Contains(t, logged, "no configured notification channel could accept the alert", "the delivery gap must be discoverable")

	// The rotation-failure audit event is about the rotation failing, not about
	// whether the alert was delivered — it must still be written and still accurate.
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAutoRotationFailures).Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

// A clean run (no failures) sends nothing.
func TestRunAutoRotation_NoFailuresNoNotify(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	sink := &fakeSink{}
	c.SetNotificationSink(sink)
	seedRotatableSecret(t, db, 1, "k", true, fixed.Add(-60*24*time.Hour)) // generated → succeeds

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Empty(t, sink.events)
}

// #391 bonus fix: failures in different projects must broadcast as separate,
// project-scoped notifications — never bundled into one cross-project message.
func TestRunAutoRotation_FailuresNotBundledAcrossProjects(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "proj-2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)

	pid1, pid2 := uint(1), uint(2)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid1, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 2, Name: "30-day", Scope: "project", ProjectID: &pid2, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)

	failA := &fakeExecutor{name: "backend-a", err: errors.New("connection refused")}
	failB := &fakeExecutor{name: "backend-b", err: errors.New("auth denied")}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{failA, failB}))

	// Project 1's secret fails via backend-a; project 2's (unrelated) secret fails via
	// backend-b. Their names/reasons must never land in the same broadcast message.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "proj1-db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationBackend: "backend-a", RotationRef: "ref-a",
		LastRotatedAt: ptrTime(fixed.Add(-60 * 24 * time.Hour)), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("orig1"), EncryptionMetadata: []byte("{}"), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "proj2-api-key", ProjectID: 2, EnvironmentID: 2, IsSecret: true, Status: "active",
		AutoRotate: true, RotationBackend: "backend-b", RotationRef: "ref-b",
		LastRotatedAt: ptrTime(fixed.Add(-60 * 24 * time.Hour)), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 2, VersionNumber: 1, EncryptedValue: []byte("orig2"), EncryptionMetadata: []byte("{}"), CreatedAt: fixed.Add(-60 * 24 * time.Hour),
	}).Error)

	sink := &fakeSink{}
	c.SetNotificationSink(sink)

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)

	require.Len(t, sink.events, 2, "one broadcast per project, never a single bundled message")
	for _, ev := range sink.events {
		assert.Equal(t, "rotation.failed", ev.Type)
		require.NotNil(t, ev.ProjectID)
		switch *ev.ProjectID {
		case 1:
			assert.Contains(t, ev.Message, "proj1-db-password")
			// Group 1 fix: raw upstream error text/backend/ref never reach an
			// external channel at all now, regardless of project.
			assert.NotContains(t, ev.Message, "connection refused", "the raw upstream error must not reach an external notification channel")
			assert.NotContains(t, ev.Message, "proj2-api-key", "project 1's broadcast must not name project 2's secret")
			assert.NotContains(t, ev.Message, "auth denied", "project 1's broadcast must not carry project 2's failure reason")
		case 2:
			assert.Contains(t, ev.Message, "proj2-api-key")
			assert.NotContains(t, ev.Message, "auth denied", "the raw upstream error must not reach an external notification channel")
			assert.NotContains(t, ev.Message, "proj1-db-password", "project 2's broadcast must not name project 1's secret")
			assert.NotContains(t, ev.Message, "connection refused", "project 2's broadcast must not carry project 1's failure reason")
		default:
			t.Fatalf("unexpected project ID %d", *ev.ProjectID)
		}
	}

	// #G23: the audit trail now records one summary PER PROJECT (each carrying that
	// project's ProjectID) rather than a single run-level summary with ProjectID=nil
	// aggregated across every project in the run.
	var auditEvents []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventAutoRotationFailures).Find(&auditEvents).Error)
	require.Len(t, auditEvents, 2)
	for _, e := range auditEvents {
		require.NotNil(t, e.ProjectID)
		assert.Contains(t, e.Description, "1 secret")
		assert.Contains(t, e.Description, fmt.Sprintf("project %d", *e.ProjectID))
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// rotationDriftStore wraps LocalStorage and fails the secret-row write, so
// RotateSecret errors AFTER the backend executor has already applied the new
// credential upstream — the split-brain / drift case.
//
// The faulted method is UpdateSecretFields since #2695 moved RotateSecret's
// last_rotated_at write onto it; the fault is injected at the same logical point
// as before (the row update that follows the upstream rotation), so this test
// pins the same property it always did.
func rotationDriftStore(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		UpdateSecretFields: func(_ storage.Storage, _ context.Context, _ uint, _ storage.SecretFieldUpdate) (bool, error) {
			return false, errors.New("simulated storage failure after upstream rotation")
		},
	})
}

// TestRunAutoRotation_BackendSucceedsStoreFails_AuditsDrift pins that the most dangerous
// rotation outcome — the upstream credential is rotated but storing the new value in Keyorix
// fails — is audited distinctly. Before the fix this path only logged + reported a generic
// failure; the live credential could drift from Keyorix's record with no audit trail. The
// backend-apply-FAILURE path was already audited; this closes the asymmetry.
func TestRunAutoRotation_BackendSucceedsStoreFails_AuditsDrift(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	// Make the post-backend store fail: RotateSecret's final UpdateSecret errors.
	c.storage = rotationDriftStore(c.storage.(*store.LocalStorage))
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the rotation did not complete — the store failed")
	require.True(t, fake.called, "the upstream backend WAS rotated (so the credential changed)")

	// Exactly one auto-rotation audit event, and it flags the drift distinctly.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Find(&events).Error)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Description, "DRIFT", "the backend-succeeded-store-failed case must be audited as drift")
	assert.Contains(t, events[0].Description, "app_svc", "the audit must name the upstream ref to reconcile")
}

// ── #193: RotateSecretOnDemand — the manual/operator rotation path must actually drive
// backend rotation for a backend-bound secret, never silently store an arbitrary
// caller-supplied value while leaving the real upstream credential untouched. ──

// fakePartialGenExecutor is a generate-upstream backend whose GenerateUpstream can
// return a rotation.PartialRotationError: the new credential is minted upstream but a
// follow-up cleanup step (deleting the prior one) fails — the new value must still be
// stored (never orphan a freshly minted, untracked credential).
type fakePartialGenExecutor struct {
	name    string
	value   string
	partial bool
	gotRef  string
}

func (f *fakePartialGenExecutor) Name() string { return f.name }
func (f *fakePartialGenExecutor) Type() string { return "fakepartial" }
func (f *fakePartialGenExecutor) Rotate(context.Context, string, string) error {
	return errors.New("use GenerateUpstream")
}
func (f *fakePartialGenExecutor) GenerateUpstream(_ context.Context, ref string) (string, error) {
	f.gotRef = ref
	if f.partial {
		return "", &rotation.PartialRotationError{Value: f.value, Err: errors.New("could not delete prior key")}
	}
	return f.value, nil
}

// A secret with no configured rotation backend rotates exactly as before: the
// caller-supplied value is stored verbatim.
func TestRotateSecretOnDemand_NoBackendStoresCallerValue(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "plain", false, fixed.Add(-24*time.Hour))

	updated, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("caller-value"), 0, "alice")
	require.NoError(t, err)
	assert.NotNil(t, updated.LastRotatedAt)
	v := latestVersion(t, db, 1)
	assert.Equal(t, "caller-value", string(v.EncryptedValue))
}

// The core #193 regression: a manual on-demand rotate of a backend-bound secret must
// actually invoke the backend rotation executor (not just overwrite the stored value),
// and the value stored in Keyorix is the one the backend applied/confirmed.
func TestRotateSecretOnDemand_AppliesBackend(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := rotationExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-24*time.Hour))

	updated, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("operator-supplied"), 0, "alice")
	require.NoError(t, err)

	require.True(t, fake.called, "the manual rotate must actually invoke the backend executor")
	assert.Equal(t, "app_svc", fake.gotRef)
	assert.Equal(t, "operator-supplied", fake.gotVal, "the caller's candidate is what gets applied upstream")

	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Equal(t, fake.gotVal, string(v.EncryptedValue), "the stored value matches what was actually applied upstream")
	assert.NotNil(t, updated.LastRotatedAt)
}

// For a generate-upstream backend the caller's candidate is ignored — the stored value
// is what the upstream minted, matching automated-rotation semantics.
func TestRotateSecretOnDemand_GenerateUpstreamIgnoresCandidate(t *testing.T) {
	fake := &fakePartialGenExecutor{name: "cloud", value: `{"access_key_id":"AKIANEW"}`}
	c, db, fixed := rotationExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-24*time.Hour))

	_, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("ignored-candidate"), 0, "alice")
	require.NoError(t, err)
	assert.Equal(t, "svc-app", fake.gotRef)
	v := latestVersion(t, db, 1)
	assert.Equal(t, fake.value, string(v.EncryptedValue))
}

// If the upstream rotation fails outright, nothing is stored — the response must never
// be a misleading "success" while the suspected-compromised credential is untouched.
func TestRotateSecretOnDemand_BackendFailureRefused(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := rotationExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-24*time.Hour))

	_, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("operator-supplied"), 0, "alice")
	require.Error(t, err, "an upstream rotation failure must never look like success")
	assert.Contains(t, err.Error(), "backend")
	assert.Contains(t, err.Error(), "NOT rotated")

	require.True(t, fake.called)
	v := latestVersion(t, db, 1)
	assert.Equal(t, 1, v.VersionNumber, "no new value is stored when the upstream apply fails")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretRotateFailed).Find(&events).Error)
	require.Len(t, events, 1, "the failure is audited distinctly")
	assert.Contains(t, events[0].Description, "app_svc")
}

// A partial upstream failure (new credential minted, prior one could not be removed)
// still stores the new value — discarding it would orphan a live, untracked credential —
// but the call still returns an error so the caller is never told "success" while a
// leftover credential needs manual removal.
func TestRotateSecretOnDemand_PartialFailureStoresButErrors(t *testing.T) {
	fake := &fakePartialGenExecutor{name: "cloud", value: `{"access_key_id":"AKIANEW"}`, partial: true}
	c, db, fixed := rotationExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-24*time.Hour))

	updated, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("ignored"), 0, "alice")
	require.Error(t, err, "a partial upstream cleanup failure must not report success")
	assert.NotNil(t, updated, "the new value is still returned/stored — never orphan a freshly minted credential")

	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Equal(t, fake.value, string(v.EncryptedValue), "the newly minted credential is stored despite the partial failure")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretRotateIncomplete).Find(&events).Error)
	require.Len(t, events, 1, "the partial outcome is audited distinctly from both success and outright failure")
}

// An unknown backend name (misconfigured after a manager reload) is refused, not
// silently treated as a plain Keyorix-only rotation.
func TestRotateSecretOnDemand_UnknownBackendRefused(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "other"}}))
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-24*time.Hour))

	_, err := c.RotateSecretOnDemand(context.Background(), 1, []byte("x"), 0, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation backend")
	v := latestVersion(t, db, 1)
	assert.Equal(t, 1, v.VersionNumber, "nothing is stored for an unresolvable backend")
}
