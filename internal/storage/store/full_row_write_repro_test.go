// full_row_write_repro_test.go — deterministic repros for the stale full-row write
// class, ported from the closed duplicate #2725 onto the #2727 guard (#2926).
// Each plays the cross-replica interleaving sequentially on one SQLite store: the
// operation's read, the concurrent writer's committed change, then the operation's
// write.
//
//   - #2696 (ClassifyMachineToken un-revoking a concurrently revoked token) is FIXED
//     (column-scoped, conditional SetMachineIdentityCredentialClassification), so its
//     repro runs as a regression test.
//   - #2695 (UpdateSecret's Save resurrecting a concurrently deleted secret) is
//     still open: docs/full-row-write-exempt.tsv carries an UNSAFE-OPEN row for
//     UpdateSecret. The repro is tied to that row rather than to a bare t.Skip: while
//     the row exists the test asserts the bug STILL reproduces (so the row cannot
//     silently go stale), and once the row is deleted the test asserts the bug is
//     gone. There is no state in which the fix lands and this stays skipped.
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func newFullRowReproStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewLocalStorage(db)
}

// A machine-token credential revoked between ClassifyMachineToken's read and its
// write must stay revoked: token auth reads `revoked` from the row (#2696).
func TestFullRowRepro_ClassifyMachineTokenKeepsConcurrentlyRevokedToken(t *testing.T) {
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	mi, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{Name: "ci", ProjectID: 1, State: "active"})
	require.NoError(t, err)
	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: mi.ID, Name: "t", TokenHash: "h"})
	require.NoError(t, err)

	stale, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID) // replica A: ClassifyMachineToken's read
	require.NoError(t, err)
	require.NoError(t, ls.RevokeMachineIdentityCredential(ctx, 1, cred.ID)) // replica B: RevokeMachineToken commits

	// replica A: its write, built from the stale read.
	matched, err := ls.SetMachineIdentityCredentialClassification(ctx, cred.ID, stale.Classification, "internal")
	require.NoError(t, err)
	require.True(t, matched, "the classification column was untouched by the revoke, so the conditional write must apply")

	got, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	require.True(t, got.Revoked, "a machine token revoked by another replica was un-revoked by a stale classification write (#2696)")
	require.Equal(t, "internal", got.Classification)
}

// The callers #2695 listed (ClassifySecret, SetSecretDescription, MoveSecret, ...)
// now write through UpdateSecretFields: a secret deleted, or suspended, between the
// caller's read and its write must not be resurrected or un-suspended.
func TestFullRowRepro_UpdateSecretFieldsKeepsConcurrentDeleteAndSuspend(t *testing.T) {
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	mk := func(name string) *models.SecretNode {
		s, err := ls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: 1, EnvironmentID: 1, Type: "password", Status: "active"})
		require.NoError(t, err)
		return s
	}
	desc := "edited on replica A"

	// Concurrent delete: must stay deleted, and the caller must be told.
	gone := mk("gone")
	_, err := ls.GetSecret(ctx, gone.ID) // replica A: the operation's read
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, gone.ID)) // replica B: DeleteSecret commits
	matched, err := ls.UpdateSecretFields(ctx, gone.ID, storage.SecretFieldUpdate{Description: &desc})
	require.NoError(t, err)
	require.False(t, matched, "a write onto a concurrently deleted secret must report matched=false")
	_, err = ls.GetSecret(ctx, gone.ID)
	require.Error(t, err, "a secret deleted by another replica was resurrected by a stale field update (#2695)")

	// Concurrent suspend: an incident freeze must survive the caller's write.
	frozen := mk("frozen")
	_, err = ls.GetSecret(ctx, frozen.ID) // replica A: the operation's read (status=active)
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", frozen.ID).Update("status", "suspended").Error) // replica B
	matched, err = ls.UpdateSecretFields(ctx, frozen.ID, storage.SecretFieldUpdate{Description: &desc})
	require.NoError(t, err)
	require.True(t, matched)
	got, err := ls.GetSecret(ctx, frozen.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "a suspension by another replica was reverted by a stale field update (#2695)")
	require.Equal(t, desc, got.Description)
}

// updateSecretOpenRowPresent reports whether the ledger still lists UpdateSecret as
// UNSAFE-OPEN, i.e. whether #2695's bug is still acknowledged as open.
func updateSecretOpenRowPresent(t *testing.T) bool {
	t.Helper()
	for _, r := range loadFullRowExempt(t) {
		if strings.HasSuffix(r.File, "local_secrets.go") && r.Func == "(*LocalStorage).UpdateSecret" && r.Model == "SecretNode" {
			return strings.HasPrefix(r.Reason, "UNSAFE-OPEN")
		}
	}
	return false
}

// secretResurrectedByStaleUpdate plays #2695: replica A reads, replica B deletes,
// replica A's UpdateSecret writes its stale row. It reports whether the secret is
// readable afterwards (i.e. was resurrected).
func secretResurrectedByStaleUpdate(t *testing.T) bool {
	t.Helper()
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 1, Type: "password", Status: "active"})
	require.NoError(t, err)

	stale, err := ls.GetSecret(ctx, sec.ID) // replica A: the operation's read
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID)) // replica B: DeleteSecret commits

	stale.Description = "edited on replica A" // replica A: its stale whole-row write
	_, err = ls.UpdateSecret(ctx, stale)
	require.NoError(t, err)

	_, err = ls.GetSecret(ctx, sec.ID)
	return err == nil
}

// A secret deleted between an UpdateSecret caller's read and its write
// (ClassifySecret, SetSecretDescription, MoveSecret, RotateSecret, ...) must stay
// deleted. GORM Save's UPDATE ... WHERE deleted_at IS NULL matches 0 rows and falls
// back to INSERT ... ON CONFLICT DO UPDATE SET deleted_at=NULL (#2695, #2689).
func TestFullRowRepro_UpdateSecretResurrectsConcurrentlyDeletedSecret(t *testing.T) {
	resurrected := secretResurrectedByStaleUpdate(t)
	if updateSecretOpenRowPresent(t) {
		require.Truef(t, resurrected,
			"the ledger lists UpdateSecret as UNSAFE-OPEN (#2689/#2695) but the stale write no longer resurrects the secret: "+
				"the bug is fixed — delete its UNSAFE-OPEN row from docs/full-row-write-exempt.tsv so this test asserts the fix")
		t.Log("#2695/#2689 still open: stale UpdateSecret resurrects a concurrently deleted secret (reproduced; tied to the ledger row)")
		return
	}
	require.False(t, resurrected, "a secret deleted by another replica was resurrected by a stale UpdateSecret (#2695)")
}
