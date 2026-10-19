// dynamic_secrets_revoke_record_nomatch_test.go — #2836 review follow-up.
//
// #2698 converted RevokeLease's two full-row lease Saves to the column-scoped
// RecordDynamicSecretLeaseRevocation, which returns (matched, error). Both call
// sites then ignored `matched`: the revoke-failed branch discarded the whole
// result with `_, _ =`, and the success branch checked only the error. A
// zero-row UPDATE therefore read, at both sites, exactly like a successful one.
//
// Why that matters on the success path specifically: the target credential is
// already dropped by then, so this is a bookkeeping hole rather than a live
// credential — but RevokeLeasesForConfig and the REST/gRPC bulk-revoke handlers
// both turn a nil return into an unconditional success report. A success nothing
// in storage corroborates is the same defect #2406's !auditOK branch exists to
// prevent, two lines further down the same function.
//
// The no-match is produced by actually DELETING the lease row — not by a stub
// returning (false, nil) — so the UPDATE really does affect zero rows, against
// the real storage, through the real method. The deletion happens inside the
// decorator, on the call immediately before the one under test, which is the
// interleaving a concurrent lease purge produces.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// leaseVanishingStorage deletes the lease row just before the revocation write
// runs, so RecordDynamicSecretLeaseRevocation matches zero rows. Everything
// else goes to the real storage underneath.
type leaseVanishingStorage struct {
	inner   storage.Storage
	db      *gorm.DB
	deleted bool
}

func (s *leaseVanishingStorage) RecordDynamicSecretLeaseRevocation(next storage.Storage, ctx context.Context, leaseID, status, revokeReason, revokeError string, revokedAt *time.Time) (bool, error) {
	if !s.deleted {
		s.deleted = true
		if err := s.db.Unscoped().Where("lease_id = ?", leaseID).Delete(&models.DynamicSecretLease{}).Error; err != nil {
			return false, err
		}
	}
	return next.RecordDynamicSecretLeaseRevocation(ctx, leaseID, status, revokeReason, revokeError, revokedAt)
}

// wrap returns inner decorated with leaseVanishingStorage's overrides.
func (s *leaseVanishingStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		RecordDynamicSecretLeaseRevocation: s.RecordDynamicSecretLeaseRevocation,
	})
}

// store returns s.inner decorated with leaseVanishingStorage's overrides.
func (s *leaseVanishingStorage) store() storage.Storage { return s.wrap(s.inner) }

// TestDynamicSecrets_RevokeLease_RevocationRecordNoMatchFailsClosed: the lease
// row is gone when the revocation write lands, so nothing recorded that this
// lease was revoked. RevokeLease must say so rather than report success.
func TestDynamicSecrets_RevokeLease_RevocationRecordNoMatchFailsClosed(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	vanishing := &leaseVanishingStorage{inner: c.storage, db: db}
	c.storage = vanishing.store()

	err = c.RevokeLease(ctx, issued.LeaseID, 7, "manual")
	require.Error(t, err,
		"a revocation that no lease row remained to record must not be reported as a clean success — "+
			"RevokeLeasesForConfig and the bulk-revoke handlers turn nil into an unconditional OK (#2836 review)")
	assert.Contains(t, err.Error(), "deleted concurrently",
		"the error must name the actual cause, so an operator is not sent looking for a backend failure")

	// Fixture precondition and the reason this is a bookkeeping gap rather than a
	// live credential: the target drop DID happen, before the row vanished. The
	// fix must not pretend otherwise, and must not retry the drop.
	require.True(t, vanishing.deleted, "the decorator never ran — the interleaving under test never happened")
	assert.Contains(t, fake.Revoked, issued.Username,
		"the target credential was dropped and that cannot be undone; the error is about the missing record")

	var rows int64
	require.NoError(t, db.Model(&models.DynamicSecretLease{}).Where("lease_id = ?", issued.LeaseID).Count(&rows).Error)
	assert.Zero(t, rows, "fixture precondition: no lease row remained for the revocation write to match")
}
