package core

// FOLLOWUP-ENV-FREEZE: the project-wide suspend takes the same per-suspension
// "also clear the synced Kubernetes copies" choice as the single-secret suspend. Each
// affected secret gets the marker exactly as SuspendSecretWithOptions gives it, ONE
// project-level audit event records the choice and the count before any secret is
// touched, resume clears the marker, and a caller who may not write a secret never
// gets it suspended or marked.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type projectSuspendWorld struct {
	c         *KeyorixCore
	db        *gorm.DB
	projectID uint
	envID     uint
}

func newProjectSuspendWorld(t *testing.T) *projectSuspendWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.SecretAccessLog{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.GroupRole{}, &models.SecretACL{}, &models.SecretAccessSchedule{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	// Actor 1 is a live project member and owns the secrets it creates.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)
	return &projectSuspendWorld{c: c, db: db, projectID: p.ID, envID: e.ID}
}

func (w *projectSuspendWorld) secret(t *testing.T, name string, owner uint, status string, marker bool) uint {
	t.Helper()
	s, err := w.c.storage.CreateSecret(context.Background(), &models.SecretNode{
		Name: name, ProjectID: w.projectID, EnvironmentID: w.envID, Type: "password", OwnerID: owner, IsSecret: true,
		Status: status, SuspendClearSyncedCopies: marker, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = w.c.storage.CreateSecretVersion(context.Background(), &models.SecretVersion{
		SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	return s.ID
}

func (w *projectSuspendWorld) stored(t *testing.T, id uint) *models.SecretNode {
	t.Helper()
	s, err := w.c.storage.GetSecret(context.Background(), id)
	require.NoError(t, err)
	return s
}

func (w *projectSuspendWorld) events(t *testing.T, eventType string) []models.AuditEvent {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, w.db.Where("event_type = ?", eventType).Order("id").Find(&evs).Error)
	return evs
}

func TestSuspendProjectSecrets_ClearSyncedCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("every affected secret gets the marker; one project event records choice and count before any effect", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		b := w.secret(t, "b", 1, SecretStatusActive, false)
		done := w.secret(t, "done", 1, SecretStatusSuspended, true) // already in the requested state

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "leaked in CI", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		for _, id := range []uint{a, b} {
			s := w.stored(t, id)
			assert.Equal(t, SecretStatusSuspended, s.Status)
			assert.True(t, s.SuspendClearSyncedCopies, "secret %d", id)
			assert.True(t, suspendedRefusal(t, w.c, id).ClearSyncedCopies, "the operator/k8s-sync must see it on secret %d", id)
		}
		assert.True(t, w.stored(t, done).SuspendClearSyncedCopies)

		bulk := w.events(t, "secret.bulk_suspend_attempted")
		require.Len(t, bulk, 1, "exactly one project-level event")
		assert.Contains(t, bulk[0].Description, "clear_synced_copies=true")
		assert.Contains(t, bulk[0].Description, "2 secret(s) targeted")
		assert.Contains(t, bulk[0].Description, "leaked in CI")
		per := w.events(t, EventSecretSuspended)
		require.Len(t, per, 2, "each affected secret keeps its own suspend event")
		for _, e := range per {
			assert.Contains(t, e.Description, "clear_synced_copies=true")
			assert.Greater(t, e.ID, bulk[0].ID, "the project event is recorded before any secret is suspended")
		}
	})

	t.Run("a plain project suspend leaves no marker and records no choice", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		n, err := w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "maintenance")
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.False(t, w.stored(t, a).SuspendClearSyncedCopies)
		assert.False(t, suspendedRefusal(t, w.c, a).ClearSyncedCopies)
		bulk := w.events(t, "secret.bulk_suspend_attempted")
		require.Len(t, bulk, 1)
		assert.NotContains(t, bulk[0].Description, "clear_synced_copies")
	})

	t.Run("an already-suspended secret is upgraded in place; an existing marker is never downgraded", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		plain := w.secret(t, "plain", 1, SecretStatusSuspended, false)
		marked := w.secret(t, "marked", 1, SecretStatusSuspended, true)

		n, err := w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "")
		require.NoError(t, err)
		assert.Equal(t, 0, n, "a plain bulk suspend has nothing to do")
		assert.False(t, w.stored(t, plain).SuspendClearSyncedCopies)
		assert.True(t, w.stored(t, marked).SuspendClearSyncedCopies, "a plain suspend never downgrades")

		n, err = w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "now known leaked", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.Equal(t, 1, n, "only the one without the marker is affected")
		assert.True(t, w.stored(t, plain).SuspendClearSyncedCopies)
		assert.True(t, w.stored(t, marked).SuspendClearSyncedCopies)
	})

	t.Run("resume-all clears the marker", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		_, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		require.True(t, w.stored(t, a).SuspendClearSyncedCopies)

		n, err := w.c.ResumeProjectSecrets(ctx, w.projectID, 1)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.False(t, w.stored(t, a).SuspendClearSyncedCopies, "the marker lives only as long as the suspension")

		_, err = w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "again")
		require.NoError(t, err)
		assert.False(t, suspendedRefusal(t, w.c, a).ClearSyncedCopies, "a later plain suspension must not inherit the old choice")
	})

	t.Run("a caller without write authority over a secret neither suspends nor marks it", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		mine := w.secret(t, "mine", 1, SecretStatusActive, false)
		theirs := w.secret(t, "theirs", 99, SecretStatusActive, false) // owned by someone else, no share/ACL for actor 1

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.True(t, w.stored(t, mine).SuspendClearSyncedCopies)
		other := w.stored(t, theirs)
		assert.Equal(t, SecretStatusActive, other.Status, "denied secret left untouched")
		assert.False(t, other.SuspendClearSyncedCopies, "and unmarked")

		bulk := w.events(t, "secret.bulk_suspend_attempted")
		require.Len(t, bulk, 1)
		assert.Contains(t, bulk[0].Description, "1 secret(s) targeted", "the count is of secrets the actor may actually affect")

		// An actor with no authority over anything: nothing happens, the attempt is still on record.
		w2 := newProjectSuspendWorld(t)
		only := w2.secret(t, "only", 99, SecretStatusActive, false)
		n, err = w2.c.SuspendProjectSecretsWithOptions(ctx, w2.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, SecretStatusActive, w2.stored(t, only).Status)
		assert.False(t, w2.stored(t, only).SuspendClearSyncedCopies)
		require.Len(t, w2.events(t, "secret.bulk_suspend_attempted"), 1)
	})

	t.Run("validates ids", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		_, err := w.c.SuspendProjectSecretsWithOptions(ctx, 0, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.Error(t, err)
		_, err = w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 0, "", SuspendOptions{ClearSyncedCopies: true})
		require.Error(t, err)
	})

	t.Run("fails closed: choice that cannot be recorded suspends nothing", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		require.NoError(t, w.db.Migrator().DropTable(&models.AuditEvent{}), "make every audit write fail")

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.ErrorIs(t, err, ErrBulkSuspendAuditUnavailable)
		assert.Zero(t, n)
		s := w.stored(t, a)
		assert.Equal(t, SecretStatusActive, s.Status, "no effect without the audit trail")
		assert.False(t, s.SuspendClearSyncedCopies)
	})

	t.Run("fails closed per secret: the bulk event is recorded but a secret's own audit row is not", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		// Call 1 is secret.bulk_suspend_attempted; call 2 is the secret's own row, inside
		// the transaction that carries its status change and marker.
		faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.True(t, faulty.Fired(), "the per-secret audit fault must be reached, or this test proves nothing")
		require.ErrorIs(t, err, ErrSuspendAuditUnavailable, "a refused per-secret audit row must surface, not be swallowed")
		var partial *BulkSuspendPartialError
		require.ErrorAs(t, err, &partial)
		assert.Equal(t, 0, partial.Suspended)
		assert.Equal(t, 1, partial.Failed)
		assert.Zero(t, n, "a secret whose audit row failed is not counted as suspended")
		s := w.stored(t, a)
		assert.Equal(t, SecretStatusActive, s.Status, "no effect without the secret's own audit row")
		assert.False(t, s.SuspendClearSyncedCopies)
		assert.Empty(t, w.events(t, EventSecretSuspended))
	})

	t.Run("a plain project suspend stays best-effort when a secret's audit row is refused", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		w.secret(t, "a", 1, SecretStatusActive, false)
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "")
		require.True(t, faulty.Fired())
		require.NoError(t, err, "revocation is never blocked by audit on a plain suspend")
		assert.Equal(t, 1, n)
	})

	t.Run("stops at the first refused per-secret audit row; earlier secrets stay suspended", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		b := w.secret(t, "b", 1, SecretStatusActive, false)
		c3 := w.secret(t, "c", 1, SecretStatusActive, false)
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		// Call 1 bulk event, call 2 first secret's row (ok), call 3 second secret's row (fails).
		faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 3, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.True(t, faulty.Fired())
		var partial *BulkSuspendPartialError
		require.ErrorAs(t, err, &partial)
		assert.Equal(t, 1, n)
		assert.Equal(t, 1, partial.Suspended)
		assert.Equal(t, 2, partial.Failed)
		suspended := 0
		for _, id := range []uint{a, b, c3} {
			if w.stored(t, id).Status == SecretStatusSuspended {
				suspended++
			}
		}
		assert.Equal(t, 1, suspended, "exactly the secret committed before the refusal is suspended")
		assert.Len(t, w.events(t, EventSecretSuspended), 1, "and it has its own audit row")
	})

	t.Run("counts a non-audit per-secret failure in clear mode: partial error, failed secret stays readable", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		ids := []uint{
			w.secret(t, "a", 1, SecretStatusActive, false),
			w.secret(t, "b", 1, SecretStatusActive, false),
			w.secret(t, "c", 1, SecretStatusActive, false),
		}
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		// One status transition per secret: the second one fails in storage.
		faulty.Arm(&faultstorage.FaultSpec{Method: "TransitionSecretStatus", NthCall: 2, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.True(t, faulty.Fired(), "the transition fault must be reached, or this test proves nothing")
		var partial *BulkSuspendPartialError
		require.ErrorAs(t, err, &partial, "a secret left readable must never be reported as success")
		assert.NotErrorIs(t, err, ErrSuspendAuditUnavailable, "a storage failure is not an audit refusal")
		assert.False(t, partial.AuditRefused)
		assert.Equal(t, 2, n)
		assert.Equal(t, 2, partial.Suspended)
		assert.Equal(t, 1, partial.Failed)
		active := 0
		for _, id := range ids {
			if w.stored(t, id).Status == SecretStatusActive {
				active++
			}
		}
		assert.Equal(t, 1, active, "exactly the failed secret is still readable")
	})

	t.Run("a plain project suspend still skips a non-audit per-secret failure", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		w.secret(t, "a", 1, SecretStatusActive, false)
		w.secret(t, "b", 1, SecretStatusActive, false)
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		faulty.Arm(&faultstorage.FaultSpec{Method: "TransitionSecretStatus", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "")
		require.True(t, faulty.Fired())
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("a storage error in the write-permission re-check is a failure in clear mode, not a denial", func(t *testing.T) {
		w := newProjectSuspendWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		faulty := faultstorage.NewFaultyStorage(w.c.storage, nil)
		w.c.storage = faulty
		// The first GetSecret is the per-secret write-permission re-check.
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})

		n, err := w.c.SuspendProjectSecretsWithOptions(ctx, w.projectID, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.True(t, faulty.Fired())
		var partial *BulkSuspendPartialError
		require.ErrorAs(t, err, &partial)
		assert.Zero(t, n)
		assert.Equal(t, 0, partial.Suspended)
		assert.Equal(t, 1, partial.Failed)
		assert.Equal(t, SecretStatusActive, w.stored(t, a).Status)
	})
}
