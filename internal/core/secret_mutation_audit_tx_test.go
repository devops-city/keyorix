package core

// secret_mutation_audit_tx_test.go — AUDIT-MUTATION-TX-1: a secret mutation's
// audit row commits in the mutation's own transaction, on SQLite and on
// PostgreSQL (set KEYORIX_TEST_PG_DSN; the Postgres leg skips without it).
//
// For every mutation kind (create, update fields, update value, rotate,
// rollback, delete, folder delete):
//   - success: the change is visible AND exactly one audit row of its type exists
//     the moment the call returns (no drain, no wait);
//   - the audit append fails (faultstorage on LogAuditEventWithAccessLog, the
//     transaction-scoped call): the call returns ErrSecretMutationAuditUnavailable
//     and the secret, its versions, its audit rows and its access logs are exactly
//     as before;
//   - effect-then-error: the append really inserts, then reports an error. Still
//     nothing may remain, which proves the row was written INSIDE the mutation's
//     transaction (a separate append would have committed it);
//   - panic: same as an error.
//
// Red on main: the mutations committed first and appended afterwards (in the
// handler), so the failure kinds left a changed secret and the success kind
// found no row from core at all.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// smaWorld is one backend with a core over faultstorage over the real store.
type smaWorld struct {
	t   *testing.T
	f   *ctaReview
	db  *gorm.DB
	fs  *faultstorage.FaultyStorage
	c   *KeyorixCore
	ctx context.Context
}

func newSMAWorld(t *testing.T, f *ctaReview) *smaWorld {
	t.Helper()
	fs := faultstorage.NewFaultyStorage(localstore.NewLocalStorage(f.dbA), nil)
	ctx := WithSecretMutationAudit(context.Background(), SecretMutationAudit{
		UserID: f.adminID, Username: "admin", IP: "198.51.100.7", UserAgent: "sma-test",
	})
	return &smaWorld{t: t, f: f, db: f.dbA, fs: fs, c: NewKeyorixCore(fs), ctx: ctx}
}

// smaBackends runs fn against SQLite (always) and PostgreSQL (when configured).
func smaBackends(t *testing.T, fn func(t *testing.T, w *smaWorld)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newSMAWorld(t, newCTAReviewSQLite(t))) })
	t.Run("postgres", func(t *testing.T) { fn(t, newSMAWorld(t, newCTAReview(t))) })
}

func (w *smaWorld) secret(name string) *models.SecretNode {
	w.t.Helper()
	s, err := w.c.CreateSecret(w.ctx, &CreateSecretRequest{
		Name: name, Value: []byte("value-1-" + name), ProjectID: w.f.projectID, EnvironmentID: w.f.envID,
		Type: "generic", CreatedBy: "admin", OwnerID: w.f.adminID,
	})
	require.NoError(w.t, err)
	return s
}

// state fingerprints everything a mutation of secret id may touch.
func (w *smaWorld) state(id uint, name string) string {
	w.t.Helper()
	var nodes []models.SecretNode
	require.NoError(w.t, w.db.Unscoped().Where("id = ? OR name = ?", id, name).Order("id").Find(&nodes).Error)
	out := ""
	for _, n := range nodes {
		out += fmt.Sprintf("node %d %q desc=%q deleted=%v rotated=%v updated=%d;", n.ID, n.Name, n.Description,
			n.DeletedAt.Valid, n.LastRotatedAt != nil, n.UpdatedAt.UnixMicro())
	}
	count := func(model any, where string, args ...any) int64 {
		var c int64
		require.NoError(w.t, w.db.Model(model).Where(where, args...).Count(&c).Error)
		return c
	}
	return out + fmt.Sprintf(" versions=%d audits=%d accesslogs=%d allaudits=%d",
		count(&models.SecretVersion{}, "secret_node_id = ?", id),
		count(&models.AuditEvent{}, "secret_node_id = ?", id),
		count(&models.SecretAccessLog{}, "secret_node_id = ?", id),
		count(&models.AuditEvent{}, "1 = 1"))
}

func (w *smaWorld) auditRows(eventType string, id uint) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.AuditEvent{}).
		Where("event_type = ? AND secret_node_id = ?", eventType, id).Count(&n).Error)
	return n
}

// smaKind is one mutation: prepare returns the target (id, name); mutate runs it.
type smaKind struct {
	name      string
	eventType string
	prepare   func(w *smaWorld, tag string) (uint, string)
	mutate    func(w *smaWorld, id uint, name string) (uint, error) // returns the audited secret id
	committed func(w *smaWorld, id uint, name string) bool
}

func smaKinds() []smaKind {
	existing := func(w *smaWorld, tag string) (uint, string) {
		s := w.secret("sma-" + tag)
		return s.ID, s.Name
	}
	rotatedOnce := func(w *smaWorld, tag string) (uint, string) {
		s := w.secret("sma-" + tag)
		_, err := w.c.RotateSecretOnDemand(w.ctx, s.ID, []byte("value-2-"+tag), w.f.adminID, "admin")
		require.NoError(w.t, err)
		return s.ID, s.Name
	}
	versions := func(w *smaWorld, id uint) int64 {
		var n int64
		require.NoError(w.t, w.db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", id).Count(&n).Error)
		return n
	}
	return []smaKind{
		{
			name: "create", eventType: "secret.created",
			prepare: func(_ *smaWorld, tag string) (uint, string) { return 0, "sma-" + tag },
			mutate: func(w *smaWorld, _ uint, name string) (uint, error) {
				s, err := w.c.CreateSecret(w.ctx, &CreateSecretRequest{
					Name: name, Value: []byte("v"), ProjectID: w.f.projectID, EnvironmentID: w.f.envID,
					Type: "generic", CreatedBy: "admin", OwnerID: w.f.adminID,
				})
				if err != nil {
					return 0, err
				}
				return s.ID, nil
			},
			committed: func(w *smaWorld, _ uint, name string) bool {
				var n int64
				require.NoError(w.t, w.db.Model(&models.SecretNode{}).Where("name = ?", name).Count(&n).Error)
				return n == 1
			},
		},
		{
			name: "update-fields", eventType: evtSecretUpdated, prepare: existing,
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) {
				d := "changed"
				_, err := w.c.UpdateSecret(w.ctx, &UpdateSecretRequest{ID: id, Description: &d, UpdatedBy: "admin"})
				return id, err
			},
			committed: func(w *smaWorld, id uint, _ string) bool {
				var s models.SecretNode
				require.NoError(w.t, w.db.First(&s, id).Error)
				return s.Description == "changed"
			},
		},
		{
			name: "update-value", eventType: evtSecretUpdated, prepare: existing,
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) {
				_, err := w.c.UpdateSecret(w.ctx, &UpdateSecretRequest{ID: id, Value: []byte("value-updated"), UpdatedBy: "admin"})
				return id, err
			},
			committed: func(w *smaWorld, id uint, _ string) bool { return versions(w, id) == 2 },
		},
		{
			name: "rotate", eventType: "secret.rotated", prepare: existing,
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) {
				_, err := w.c.RotateSecretOnDemand(w.ctx, id, []byte("value-rotated"), w.f.adminID, "admin")
				return id, err
			},
			committed: func(w *smaWorld, id uint, _ string) bool { return versions(w, id) == 2 },
		},
		{
			name: "rollback", eventType: EventSecretRolledBack, prepare: rotatedOnce,
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) {
				_, err := w.c.RollbackSecret(w.ctx, id, 1, w.f.adminID, "admin")
				return id, err
			},
			committed: func(w *smaWorld, id uint, _ string) bool { return versions(w, id) == 3 },
		},
		{
			name: "delete", eventType: "secret.deleted", prepare: existing,
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) { return id, w.c.DeleteSecret(w.ctx, id) },
			committed: func(w *smaWorld, id uint, _ string) bool {
				var s models.SecretNode
				require.NoError(w.t, w.db.Unscoped().First(&s, id).Error)
				return s.DeletedAt.Valid
			},
		},
		{
			name: "folder-delete", eventType: "secret.deleted",
			prepare: func(w *smaWorld, tag string) (uint, string) {
				fo, err := w.c.CreateFolder(context.Background(), w.f.adminID, "sma-"+tag, w.f.projectID, w.f.envID, nil)
				require.NoError(w.t, err)
				return fo.ID, fo.Name
			},
			mutate: func(w *smaWorld, id uint, _ string) (uint, error) {
				return id, w.c.DeleteSecretWithPermissionCheck(w.ctx, id, w.f.adminID)
			},
			committed: func(w *smaWorld, id uint, _ string) bool {
				var s models.SecretNode
				require.NoError(w.t, w.db.Unscoped().First(&s, id).Error)
				return s.DeletedAt.Valid
			},
		},
	}
}

func TestSecretMutationAudit_RowExistsIffMutationCommitted(t *testing.T) {
	smaBackends(t, func(t *testing.T, w *smaWorld) {
		for _, k := range smaKinds() {
			t.Run(k.name+"/success", func(t *testing.T) {
				id, name := k.prepare(w, k.name+"-ok")
				got, err := k.mutate(w, id, name)
				require.NoError(t, err)
				require.True(t, k.committed(w, got, name), "precondition: the mutation must have committed")
				require.EqualValues(t, 1, w.auditRows(k.eventType, got),
					"%s committed, so exactly one %s row must exist when the call returns", k.name, k.eventType)
			})
			for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError, faultstorage.KindPanic} {
				t.Run(k.name+"/audit-"+fk.String(), func(t *testing.T) {
					id, name := k.prepare(w, k.name+"-"+fk.String())
					before := w.state(id, name)
					w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEventWithAccessLog", NthCall: 1, Kind: fk, Err: errors.New("injected audit failure")})
					_, err := func() (_ uint, err error) {
						defer func() {
							if r := recover(); r != nil {
								err = fmt.Errorf("panic escaped the mutation: %v", r)
							}
						}()
						return k.mutate(w, id, name)
					}()
					fired := w.fs.Fired()
					w.fs.Arm(nil)
					require.True(t, fired, "%s never appended its audit row through storage", k.name)
					require.ErrorIs(t, err, ErrSecretMutationAuditUnavailable, "a failed audit append must fail the mutation")
					require.False(t, k.committed(w, id, name), "%s committed although its audit row could not be written", k.name)
					require.Equal(t, before, w.state(id, name),
						"a failed audit append must leave the secret, its versions, audit rows and access logs unchanged")
				})
			}
		}
		v, err := w.c.Storage().VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every success and every rolled-back attempt: %s", v.Reason)
	})
}

// TestSecretMutationAudit_NoContextNoRow: a mutation called without
// WithSecretMutationAudit (internal callers that audit separately — bulk delete,
// copy, the rotation scheduler) writes no mutation row of its own, so this
// change adds no duplicate rows to them.
func TestSecretMutationAudit_NoContextNoRow(t *testing.T) {
	f := newCTAReviewSQLite(t)
	w := newSMAWorld(t, f)
	s := w.secret("sma-plain")
	_, err := w.c.RotateSecret(context.Background(), s.ID, []byte("value-plain-2"), f.adminID, "admin")
	require.NoError(t, err)
	require.NoError(t, w.c.DeleteSecret(context.Background(), s.ID))
	require.Zero(t, w.auditRows("secret.rotated", s.ID))
	require.Zero(t, w.auditRows("secret.deleted", s.ID))
}
