package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/secrettemplate"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newRenderFixture builds an in-memory core with a project, a "production"
// environment, and a secret "db-password"=s3cr3t owned by user 1.
func newRenderFixture(t *testing.T) (*KeyorixCore, *gorm.DB, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{},
		&models.Project{}, &models.Environment{}, &models.SecretAccessLog{}, &models.AuditEvent{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.SecretAccessSchedule{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@test.com"}).Error)

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj.ID}).Error)
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t"),
	})
	require.NoError(t, err)
	return c, db, proj.ID, secret.ID
}

func TestRenderSecretTemplate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, projectID, _ := newRenderFixture(t)

	t.Run("expands a known reference", func(t *testing.T) {
		out, err := c.RenderSecretTemplate(ctx, "DB=${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.NoError(t, err)
		assert.Equal(t, "DB=s3cr3t", out)
	})

	t.Run("unknown environment fails", func(t *testing.T) {
		// TMPL-002: unknown environment uses ErrSecretRefNotFound so the HTTP handler
		// doesn't reflect the environment name to the caller.
		_, err := c.RenderSecretTemplate(ctx, "${secret:staging/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("unknown secret fails", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/nope}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("non-reader cannot resolve", func(t *testing.T) {
		// User 2 owns nothing and has no share → the per-secret read check denies.
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
	})

	t.Run("requires project + user", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "x", 0, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		_, err = c.RenderSecretTemplate(ctx, "x", projectID, 0, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
	})
}

// #181: a nonexistent secret and an existing-but-forbidden secret must be
// indistinguishable to the caller — both resolve to the ErrSecretRefNotFound sentinel,
// which the HTTP handler maps to the identical generic 404 regardless of which case it
// was, so a viewer can't use the render endpoint as a 404-vs-403 existence oracle to
// enumerate real secret names. (The handler-level response-body equivalence is asserted
// in server/http/handlers/secrets_render_test.go; here we assert the underlying sentinel
// the handler switches on is the same for both branches — using the SAME reference for
// both queries so the resolver's own "resolve %q" wrapping can't introduce a difference.)
func TestRenderSecretTemplate_UniformResponseForNotFoundVsForbidden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, projectID, secretID := newRenderFixture(t)

	// User 2 owns nothing and has no share on "db-password", which DOES exist.
	_, forbiddenErr := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.Error(t, forbiddenErr)
	require.ErrorIs(t, forbiddenErr, ErrSecretRefNotFound, "forbidden case must surface the same sentinel as not-found")

	// Same reference text, but the owning user deletes it first so it truly doesn't
	// exist — this isolates the sentinel/message from the "resolve %q" reference echo.
	require.NoError(t, c.DeleteSecret(ctx, secretID))
	_, notFoundErr := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.Error(t, notFoundErr)
	require.ErrorIs(t, notFoundErr, ErrSecretRefNotFound, "not-found case must surface the ErrSecretRefNotFound sentinel")

	assert.Equal(t, notFoundErr.Error(), forbiddenErr.Error(), "response for a forbidden secret must be byte-identical to a nonexistent one once the reference text matches")
}

// A render records a secret read (access log) for each resolved reference, so a bulk
// render can't be a covert exfiltration channel invisible to the audit trail and the
// anomaly detector (which feeds on SecretAccessLog).
func TestRenderSecretTemplate_RecordsReads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, projectID, _ := newRenderFixture(t)

	_, err := c.RenderSecretTemplate(ctx, "DB=${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)

	// The read is logged in a detached goroutine — poll briefly for the access-log row.
	var n int64
	for range 200 {
		require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Positive(t, n, "a resolved render reference must produce a secret access-log row")
}

// #324: rendering a template referencing N distinct secrets must produce N audit_events
// rows and N secret_access_logs rows — one per resolved secret, each attributed to the
// correct secret ID — not one aggregate event for the whole render call. Without this,
// a single POST could bulk-decrypt an arbitrary number of secrets while leaving the
// anomaly detector (which keys off per-secret SecretAccessLog rows) completely blind,
// exactly matching the fetch-N-individually-vs-render-once asymmetry #324 called out.
func TestRenderSecretTemplate_RecordsReadPerSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, projectID, _ := newRenderFixture(t)

	// Add two more secrets to the same project/environment alongside db-password.
	env, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, env, 1)

	apiKey, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "api-key", ProjectID: projectID, EnvironmentID: env[0].ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: apiKey.ID, VersionNumber: 1, EncryptedValue: []byte("a-p-i"),
	})
	require.NoError(t, err)

	stripeKey, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "stripe-secret", ProjectID: projectID, EnvironmentID: env[0].ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: stripeKey.ID, VersionNumber: 1, EncryptedValue: []byte("sk_live_xyz"),
	})
	require.NoError(t, err)

	dbSecret, err := c.storage.GetSecretByName(ctx, "db-password", projectID, env[0].ID)
	require.NoError(t, err)

	tmpl := "${secret:production/db-password}${secret:production/api-key}${secret:production/stripe-secret}"
	out, err := c.RenderSecretTemplate(ctx, tmpl, projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)
	assert.Equal(t, "s3cr3ta-p-isk_live_xyz", out)

	wantSecretIDs := []uint{dbSecret.ID, apiKey.ID, stripeKey.ID}

	// Reads are logged in detached goroutines — poll briefly for all three rows.
	var gotAccessLogIDs []uint
	var gotAuditSecretIDs []*uint
	for range 200 {
		var logs []models.SecretAccessLog
		require.NoError(t, db.Where("accessed_by = ? AND action = ?", "owner", "read").Find(&logs).Error)
		gotAccessLogIDs = nil
		for _, l := range logs {
			gotAccessLogIDs = append(gotAccessLogIDs, l.SecretNodeID)
		}

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", "secret.read").Find(&events).Error)
		gotAuditSecretIDs = nil
		for _, e := range events {
			gotAuditSecretIDs = append(gotAuditSecretIDs, e.SecretNodeID)
		}

		if len(gotAccessLogIDs) >= 3 && len(gotAuditSecretIDs) >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	assert.ElementsMatch(t, wantSecretIDs, gotAccessLogIDs,
		"one secret_access_logs row per resolved secret, correctly attributed")
	require.Len(t, gotAuditSecretIDs, 3, "one audit_events row per resolved secret, not one aggregate event")
	var gotAuditIDs []uint
	for _, id := range gotAuditSecretIDs {
		require.NotNil(t, id, "each secret.read audit event must carry the specific secret's ID")
		gotAuditIDs = append(gotAuditIDs, *id)
	}
	assert.ElementsMatch(t, wantSecretIDs, gotAuditIDs)

	// Every audit event must also carry the project ID for scoping.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "secret.read").Find(&events).Error)
	for _, e := range events {
		require.NotNil(t, e.ProjectID)
		assert.Equal(t, projectID, *e.ProjectID)
	}
}

// #443: a template that repeats the SAME reference many times must resolve (decrypt)
// it exactly once and log exactly one secret read — not once per occurrence. Without
// this, a caller could submit a template with thousands of repeated references to one
// secret to force thousands of redundant decryptions and audit rows for what is, in
// substance, a single read. This exercises the fix end-to-end through the real
// GetSecretValue/audit-logging path, not just the pure secrettemplate.Render layer.
func TestRenderSecretTemplate_DedupesRepeatedReference(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, projectID, _ := newRenderFixture(t)

	var tmpl string
	for range 50 {
		tmpl += "${secret:production/db-password}"
	}
	out, err := c.RenderSecretTemplate(ctx, tmpl, projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)

	var want string
	for range 50 {
		want += "s3cr3t"
	}
	assert.Equal(t, want, out, "every occurrence still substitutes the resolved value")

	// Reads are logged in a detached goroutine — poll briefly, then assert the count
	// settles at exactly one (not 50).
	var n int64
	for range 200 {
		require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Give any (incorrect) duplicate log writes a moment to land before the final count.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
	assert.EqualValues(t, 1, n, "50 occurrences of the same reference must produce exactly one access-log row")

	var eventCount int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.read").Count(&eventCount).Error)
	assert.EqualValues(t, 1, eventCount, "50 occurrences of the same reference must produce exactly one audit event")
}

// #443: a template naming more distinct references than
// secrettemplate.MaxDistinctReferences must be rejected before any secret is resolved
// (no partial reads, no audit rows), even though most callers legitimately need far
// fewer.
func TestRenderSecretTemplate_RejectsTooManyDistinctReferences(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, projectID, _ := newRenderFixture(t)

	var tmpl string
	for i := range secrettemplate.MaxDistinctReferences + 1 {
		tmpl += fmt.Sprintf("${secret:production/ref-%d}", i)
	}
	_, err := c.RenderSecretTemplate(ctx, tmpl, projectID, 1, "owner", "10.0.0.1", "ua")
	require.Error(t, err)

	time.Sleep(20 * time.Millisecond) // let any (incorrect) stray audit writes land
	var n int64
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Count(&n).Error)
	assert.Zero(t, n, "an over-cap template must be rejected before resolving/reading any secret")
}

// callRecordingStorage wraps a real *store.LocalStorage and records the sequence
// of GetSecret / GetSecretByName / GetLatestSecretVersion calls made through it,
// delegating every other method (and the real behavior of these three) to the
// embedded implementation. Used by
// TestRenderSecretTemplate_EqualizesResolutionCostShape to assert the SAME SET
// of storage calls happens whether a reference doesn't exist, exists but is
// forbidden, or exists and is readable — the timing side-channel closed by
// equalizeReferenceResolutionCost in secret_render.go.
type callRecordingStorage struct {
	*store.LocalStorage
	mu    sync.Mutex
	calls []string
}

func (s *callRecordingStorage) record(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name)
}

func (s *callRecordingStorage) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

func (s *callRecordingStorage) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

func (s *callRecordingStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	s.record("GetSecret")
	return s.LocalStorage.GetSecret(ctx, id)
}

func (s *callRecordingStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	s.record("GetSecretByName")
	return s.LocalStorage.GetSecretByName(ctx, name, projectID, environmentID)
}

func (s *callRecordingStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	s.record("GetLatestSecretVersion")
	return s.LocalStorage.GetLatestSecretVersion(ctx, secretID)
}

// #<timing finding>: RenderSecretTemplate's per-reference resolution must perform
// the SAME SHAPE of DB lookup work — GetSecretByName, GetSecret, and
// GetLatestSecretVersion all invoked — whether the reference doesn't exist,
// exists but is forbidden, or exists and is readable. Before the fix, a
// nonexistent reference returned after GetSecretByName alone (skipping GetSecret
// and GetLatestSecretVersion entirely) and a forbidden reference returned after
// GetSecretByName + GetSecret (skipping GetLatestSecretVersion) — cheaper, and
// therefore measurably faster, than the readable case. A caller who can submit
// templates with guessed references and measure response time could use that
// gap to tell "doesn't exist" apart from "exists but forbidden" apart from
// "exists and readable", defeating this function's own anti-enumeration design
// (#181). This is a structural stand-in for a true timing measurement (flaky in
// a unit test): it asserts the call SET is now uniform, which is what makes the
// three cases' cost uniform.
func TestRenderSecretTemplate_EqualizesResolutionCostShape(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, projectID, _ := newRenderFixture(t)

	realStorage, ok := c.storage.(*store.LocalStorage)
	require.True(t, ok, "fixture must back RenderSecretTemplate with *store.LocalStorage")
	spy := &callRecordingStorage{LocalStorage: realStorage}
	c.storage = spy

	wantCalls := []string{"GetSecretByName", "GetSecret", "GetLatestSecretVersion"}

	spy.reset()
	_, err := c.RenderSecretTemplate(ctx, "${secret:production/does-not-exist}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.Error(t, err)
	notFoundCalls := spy.snapshot()

	spy.reset()
	// User 2 owns nothing and has no share on db-password, which DOES exist.
	_, err = c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.Error(t, err)
	forbiddenCalls := spy.snapshot()

	spy.reset()
	_, err = c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)
	readableCalls := spy.snapshot()

	cases := map[string][]string{
		"not-found": notFoundCalls,
		"forbidden": forbiddenCalls,
		"readable":  readableCalls,
	}
	for label, calls := range cases {
		got := make(map[string]bool, len(calls))
		for _, c := range calls {
			got[c] = true
		}
		for _, want := range wantCalls {
			assert.True(t, got[want], "%s case: expected a %s call among %v", label, want, calls)
		}
	}
}

// #<rollback finding>: a template naming N references where a LATER one fails
// must not leave the earlier, successfully-resolved-but-ultimately-discarded
// references "half charged" — no secret.read audit event, no access-log row,
// and no max-reads budget consumed for any of them, since the overall render
// produced no output. Extends the documented "fails the whole render, no
// partial output" contract to RenderSecretTemplate's side effects, not just its
// return value — otherwise a caller could submit a large template naming many
// real references plus one deliberately-failing one to burn through a read
// budget and flood the audit trail with reads that delivered nothing.
func TestRenderSecretTemplate_NoSideEffectsWhenLaterReferenceFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, projectID, dbSecretID := newRenderFixture(t)

	envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, envs, 1)

	maxReads := 5
	apiKey, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "api-key", ProjectID: projectID, EnvironmentID: envs[0].ID, Type: "password",
		OwnerID: 1, IsSecret: true, MaxReads: &maxReads, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: apiKey.ID, VersionNumber: 1, EncryptedValue: []byte("a-p-i"),
	})
	require.NoError(t, err)

	// The first two references resolve cleanly; the third names a secret that
	// doesn't exist, so the whole render fails.
	tmpl := "${secret:production/db-password}${secret:production/api-key}${secret:production/does-not-exist}"
	_, err = c.RenderSecretTemplate(ctx, tmpl, projectID, 1, "owner", "10.0.0.1", "ua")
	require.Error(t, err)

	// Give any (incorrect) stray audit/access-log writes a moment to land before
	// asserting they never happened.
	time.Sleep(30 * time.Millisecond)

	var accessLogs int64
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Count(&accessLogs).Error)
	assert.Zero(t, accessLogs, "no secret_access_logs row for any reference in a template whose render ultimately failed")

	var auditEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND success = ?", "secret.read", true).Count(&auditEvents).Error)
	assert.Zero(t, auditEvents, "no successful secret.read audit event for any reference in a template whose render ultimately failed")
	// #3273: the one refused reference is audited, as a refusal (one row, not
	// one per reference: the resolved ones delivered nothing and are not reads).
	var refused []models.AuditEvent
	require.NoError(t, db.Where("event_type = ? AND success = ?", "secret.read", false).Find(&refused).Error)
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Description, "reason=not_found")

	reloadedAPIKey, err := c.storage.GetSecret(ctx, apiKey.ID)
	require.NoError(t, err)
	assert.Zero(t, reloadedAPIKey.ReadCount, "max-reads budget must not be consumed for a reference in a template whose render ultimately failed")

	reloadedDB, err := c.storage.GetSecret(ctx, dbSecretID)
	require.NoError(t, err)
	assert.Zero(t, reloadedDB.ReadCount)
}
